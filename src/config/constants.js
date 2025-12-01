// src/config/constants.js
// Extracted from attack_timearcs.js

export const MARGIN = { top: 40, right: 20, bottom: 30, left: 110 };
export const DEFAULT_WIDTH = 1200;
export const DEFAULT_HEIGHT = 600;
export const INNER_HEIGHT = 780;

export const PROTOCOL_COLORS = new Map([
  ['TCP', '#1f77b4'],
  ['UDP', '#2ca02c'],
  ['ICMP', '#ff7f0e'],
  ['GRE', '#9467bd'],
  ['ARP', '#8c564b'],
  ['DNS', '#17becf'],
]);

export const DEFAULT_COLOR = '#6c757d';
export const NEUTRAL_GREY = '#9e9e9e';

export const LENS_DEFAULTS = {
  magnification: 5,
  bandRadius: 0.045,
};

export const FISHEYE_DEFAULTS = {
  distortion: 5,
  effectRadius: 0.5,
};
