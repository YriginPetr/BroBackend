const httpStatus = require('http-status');

const crypto = require('crypto');
const ApiError = require('../utils/ApiError');
const config = require('../config/config');

const verifyLaunchParams = function verifyLaunchParams(searchOrParsedUrlQuery, secretKey) {
  let sign;
  const queryParams = [];
  const processQueryParam = (key, value) => {
    if (typeof value === 'string') {
      if (key === 'sign') {
        sign = value;
      } else if (key.startsWith('vk_')) {
        queryParams.push({ key, value });
      }
    }
  };

  Object.keys(searchOrParsedUrlQuery).forEach((key) => {
    const value = searchOrParsedUrlQuery[key];
    processQueryParam(key, value);
  });

  if (!sign || queryParams.length === 0) {
    return false;
  }

  const queryString = queryParams

    .sort((a, b) => a.key.localeCompare(b.key))

    .reduce((acc, { key, value }, idx) => {
      return `${acc + (idx === 0 ? '' : '&')}${key}=${encodeURIComponent(value)}`;
    }, '');

  const paramsHash = crypto
    .createHmac('sha256', secretKey)
    .update(queryString)
    .digest()
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=$/, '');

  return paramsHash === sign;
};

const auth = () => async (req, res, next) => {
  try {
    const areLaunchParamsValid = verifyLaunchParams(req.header('Authorization'), config.vkma.secret);
    if (areLaunchParamsValid) {
      next();
    } else {
      next(ApiError(httpStatus.UNAUTHORIZED, 'Check url params'));
    }
  } catch (err) {
    next(ApiError(httpStatus.UNAUTHORIZED, 'Check url params'));
  }
};

module.exports = auth;
