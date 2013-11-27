package demo.scala

import com.sun.jna.{Native, Library}
import com.sun.jna.ptr.PointerByReference

/**
 * User: ya_feng_li@163.com
 * Date: 13-11-12
 * Time: 上午9:07
 */
trait CplusLib extends Library {
  def d_say(str: String)

  def d_add(a: Int, b: Int): Int
}

object CplusLib {
  val INSTANCE = Native.loadLibrary("demo", classOf[CplusLib]).asInstanceOf[CplusLib]
}

trait CLib extends Library {
  def j_say(str: String, pstr: PointerByReference)

  def j_add(a: Int, b: Int): Int
}

object CLib {
  val INSTANCE = Native.loadLibrary("test", classOf[CLib]).asInstanceOf[CLib]
}