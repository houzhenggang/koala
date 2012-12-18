package org.koala.scala.core

/**
 * 隐式转换String to IP 二进制的转换操作；
 * @param str
 */
class IPMix(str: String) {
  def toBinary: Int = {
    val ips = str.split("\\.")
    if (ips == null || ips.length != 4) {
      throw new NumberFormatException()
    }
    (ips(0).toInt << 24) + (ips(1).toInt << 16) + (ips(2).toInt << 8) + ips(3).toInt
  }

  def toNetBinary: Int = {
    val ips = str.split("\\.")
    if (ips == null || ips.length != 4) {
      throw new NumberFormatException()
    }
    (ips(3).toInt << 24) + (ips(2).toInt << 16) + (ips(1).toInt << 8) + ips(0).toInt
  }
}

object IPMix {
  implicit def ip(str: String) = new IPMix(str)
}