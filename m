Return-Path: <kasan-dev+bncBDTMJ55N44FBBC4E5O7AMGQE4QU3JBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DFDEA68D6D
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 14:09:37 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-43947979ce8sf22848805e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 06:09:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742389772; cv=pass;
        d=google.com; s=arc-20240605;
        b=dHEfT5lk9E7T/UUylskakDmg7XoC0behLn+XOFbPDng3de7J3ZvmaJ1qzwPvosj5LJ
         hmeJZUR0zfkoV5McmaO4PgfLtwkNQbTANtieZohpX9CvgYREnh2bUVSM8fEKiJD1e+yG
         gNPqzURilqadpKSWGoIrlc8ajMko2vYSDXClZndA1OrxRhL9gJfBdNPYma86nz5F4epZ
         T9IlUcTjGC+fgnzEZaCKGtu8p2nBFnYwNgKS0TN65sA7YettGL40WyYJWWZrJEKmAI19
         w05eIG8DJ3X0bBhACuzY2b/iiCg/gdLVgXATDwXFo5SPoicRQqg99ubTeooNC4x5+rNM
         X4BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=OatHXqFS9YfS1y/9BXlYSf+JqncyaymSHS0MNp9FfvY=;
        fh=Bf+n9hd/cc8sb4jXbrzEqMS0TvKuQUmEYsDd3Jo2U40=;
        b=FItf+TxVfArCrIc5IEQhJY0RAPCa3zTSHbGO2u6Dyffb73uYTEg4Q2YkLjDZl47gR9
         V0aC/GRN4S70r2fivZO/myJlntoV6fG2aSelyJzuLpGFf7PQdPG+YZPeCO54pl7xwmro
         Q24keIjLhZfGxyYWX855i197R+BPJKSubLYq81kzHTI5OmnfOfnJHE/j8WaMI49sZge5
         6TKoyxcF6GPrB3pjdy9qQFXSFBdGOtMTbTZTaqhiyvVuYjWKB99SIL9g3UvbRisMmuD9
         XSEQWrKlGgt/8EBgY2aPePCcJF56XWwMrlP8fg/T9O5MwBH3OJpN1t/ClAbH0bkU7+rt
         tQ2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.43 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742389772; x=1742994572; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OatHXqFS9YfS1y/9BXlYSf+JqncyaymSHS0MNp9FfvY=;
        b=IC3nz+ejrof3dCJhqSDu0nDVwE7p160UcURICY7p/00psWxTJLKRZeTPW+a2YLb1KW
         b3KzOpYRdYuo4UFmxao2KetRwiV0XjirnmEjs1NRaPWaEEWTPS9rcjMUr0jkfhoK7cCl
         modkzSRFIqJrMhMoSTTHwoBlFFx/5v1cw9QofTB4lbdINESFDZtNMBHFOvbEf820NSz0
         LNJp2KFAWoVtEqYAaI8Zzz69jfAEjBBVVl6ARKn7+Vsit9q3Ytk0T1StgVYhRUlTrmQp
         co5J1d/YD0sZDbX0Zxis6QeCR4n8pYyqeAHq+PfsbTI2RknrOEbVgC6wAuKoc9qixWgs
         buwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742389772; x=1742994572;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OatHXqFS9YfS1y/9BXlYSf+JqncyaymSHS0MNp9FfvY=;
        b=THxXS3UOOQBctHH2yqS0+fY3eQMne6h8cfjnYo3ky0w50FOyThSlMl31NMiqfP9pmP
         xXliX1+AAjyhx9j95xu2EXfvlrkv6PnyE3oz+J4vnHw4T0AeLRldGAGbv8nTsJNoPntB
         RMqOzX+jNQFdXgan9UmqhCtFrl8lAUteGYjqfdalUhZD8HOq7QqUxxHL0m0AUUmjVDVO
         j5mEZDHTqGKfJan9syD1m+aA0T6PIYGKdMNd/ksAkYsU3rlwMdOcW3WgaOj6lT5jPVc9
         SWSvuGI2E+uXfMdzlitYIhDS5n6Bn33d8EEfHp2Xbr+dCWc9TiCUXyfFMBVrMtvRpHB3
         /5Ag==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbpU7WTjOkmq0cO2HNweQsaqizyAoiFoYOLgoYpiNWvlhk3vnenz6SExx0fMDjh0gNEbmtvA==@lfdr.de
X-Gm-Message-State: AOJu0YydWvau3O5uJxerN3iF5BKuecKOfpd4/f2pbUQ5nd6wRmWwH91e
	/IVkH6UADDXueLD/t/WnfZjuNc2Q2inTrJINvo9j7Irm9xaFJv0m
X-Google-Smtp-Source: AGHT+IGpg+3PRpUu6P4wxMezcUiBeozRmSZu/EsvcGOx70fbMIMuf3C6i/sqp/HNt8i3acflzI8MTg==
X-Received: by 2002:a05:600c:19d2:b0:43c:f050:fee8 with SMTP id 5b1f17b1804b1-43d437e1703mr20224365e9.20.1742389772024;
        Wed, 19 Mar 2025 06:09:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAI4B6eN16VbHRhgjGd8e9jQcOzTCuSDveLE+Be7r7RD8w==
Received: by 2002:a05:600c:6a06:b0:43d:40b0:33 with SMTP id
 5b1f17b1804b1-43d40b00198ls5423795e9.0.-pod-prod-01-eu; Wed, 19 Mar 2025
 06:09:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUL0TT80nlpe+EqZCcCJidKiGAVUrXIeFM2MIFcg8BcXtDzV2+TJDaCGDx8bNmHKijIjqVQtl9p4CM=@googlegroups.com
X-Received: by 2002:a05:600c:5009:b0:43b:b756:f0a9 with SMTP id 5b1f17b1804b1-43d4378b215mr30155045e9.11.1742389768834;
        Wed, 19 Mar 2025 06:09:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742389768; cv=none;
        d=google.com; s=arc-20240605;
        b=bDHw5fsOVwIFzjNGIqgqaW0qDipc2qcaXXQm4U/6CFDQgkeiUv3OcBwVvkuDWY3A0G
         +OIhch4T6w9Xon1O3IXMAg7kcC/BNkXiMXRY4mBVILzMQR+DyY2XBDi0PU5sVUbHu0oZ
         KhBRDrHyXdIXo0mWjdqRKHtjC7yCII3udsO+j1lnkbnbIUE/6YyS3D5u4jlDQRhozhNd
         Hg9uc3jOqaUDVBlsa2LL1oDiNeUUUTDNGkZdjWaDv3AWzrKX+1+mLujvRkosuxaKv04F
         T/8nifQHA4T9HxhoOS5o6smirfLd9ZP8KFet7sxKsztDnXXMywJDP4Dihf2n71WlVADT
         Zjmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date;
        bh=nJhYfF5JEpYxjTWV7EegPtHsuLvj4MI6+wwi3tL7P2A=;
        fh=o2ofKQbnFvl4diP2ag9yxX9VFhZ+0tUGW6C4R1X8D+s=;
        b=FQi8RVRPmeaywazN9Ysjkk8rXuRhW5uZr43KhKAlnUP//KmsajEtOmliNfrgZGoeXs
         vvawFFbgMurx7nIBgwoJmrnfpz1mvx+gHlGsGeOFaOSCuBAnDFZ4s9dSkfdOpiWLfYhx
         eCqhhPT7pwyYFgQVf7AeMcxMGGXJLe5l2ZVvh3OTbzSVOl5Rgk6bMSKLk1C45/O82qqJ
         mnwk04N2aJXdmCsISFO0q+y3L7ezILgc3lJvTrfGPh8XpophTyNqwrh6PQe+phSuzw7S
         tbHmwsWGOZ6ytAsK5ZrnqimjVpeh6ij/cFv2XpLVaVM+ZLEf7E+iryttJkY7lqn3M6Di
         1R4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.43 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ed1-f43.google.com (mail-ed1-f43.google.com. [209.85.208.43])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d3ad4807esi1568005e9.0.2025.03.19.06.09.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Mar 2025 06:09:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.43 as permitted sender) client-ip=209.85.208.43;
Received: by mail-ed1-f43.google.com with SMTP id 4fb4d7f45d1cf-5e686d39ba2so12769351a12.2
        for <kasan-dev@googlegroups.com>; Wed, 19 Mar 2025 06:09:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVK2Z63VUxQqZoo0QNpg5bvzRJESyJ3zeHuFmNIQuxxwv+R9nQdueQiKyjKK2hk4ixo3K/FGEP12Mc=@googlegroups.com
X-Gm-Gg: ASbGnctPv0Dx3mWH/+ZYGlB4ds7CUx6lI1eh+ikYjrDgt4Yb3tYrIe9pdfHSWUbAYlt
	IIvs5Y93aR5xBtJtmwi3nSXfyUtUKwMPC8fWyBewSCMhQxcUEiqBylZ2y74ar7k/h3qBYmVI2vF
	bf2i3YrEQkluxaaqcY+34LTtSHJtp7cPBCKO1x0KDk6lGSORwJku19cRclrwJR08eHPEYRiO4ea
	cjooTwxBANuU0OXt0bAz22JsMgNISUTO1svqnF/QPamF5mofpN6jVyp8pIeqQLVkuUALU+09UFy
	yY1VcMnSbLvfkRNMtn+roy9ix2yAVSv4iETC
X-Received: by 2002:a05:6402:5201:b0:5e7:aeb9:d0cc with SMTP id 4fb4d7f45d1cf-5eb80caa1bbmr2502278a12.3.1742389756373;
        Wed, 19 Mar 2025 06:09:16 -0700 (PDT)
Received: from gmail.com ([2a03:2880:30ff:73::])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-5e816968aefsm9519196a12.20.2025.03.19.06.09.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Mar 2025 06:09:15 -0700 (PDT)
Date: Wed, 19 Mar 2025 06:09:12 -0700
From: Breno Leitao <leitao@debian.org>
To: paulmck@kernel.org, kuba@kernel.org, jhs@mojatatu.com,
	xiyou.wangcong@gmail.com, jiri@resnulli.us
Cc: edumazet@google.com, kuniyu@amazon.com, rcu@vger.kernel.org,
	kasan-dev@googlegroups.com, netdev@vger.kernel.org
Subject: tc: network egress frozen during qdisc update with debug kernel
Message-ID: <20250319-meticulous-succinct-mule-ddabc5@leitao>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.208.43 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Hello,

I am experiencing an issue with upstream kernel when compiled with debug
capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and
CONFIG_LOCKDEP plus a few others. You can find the full configuration at
https://pastebin.com/Dca5EtJv.

Basically when running a `tc replace`, it takes 13-20 seconds to finish:

        # time /usr/sbin/tc qdisc replace dev eth0 root handle 0x1234: mq
	real	0m13.195s
	user	0m0.001s
	sys	0m2.746s

While this is running, the machine loses network access completely. The
machine's network becomes inaccessible for 13 seconds above, which is far from
ideal.

Upon investigation, I found that the host is getting stuck in the following
call path:

        __qdisc_destroy
        mq_attach
        qdisc_graft
        tc_modify_qdisc
        rtnetlink_rcv_msg
        netlink_rcv_skb
        netlink_unicast
        netlink_sendmsg

The big offender here is rtnetlink_rcv_msg(), which is called with rtnl_lock
in the follow path:

	static int tc_modify_qdisc() {
		...
		netdev_lock_ops(dev);
		err = __tc_modify_qdisc(skb, n, extack, dev, tca, tcm, &replay);
		netdev_unlock_ops(dev);
		...
	}

So, the rtnl_lock is held for 13 seconds in the case above. I also
traced that __qdisc_destroy() is called once per NIC queue, totalling
a total of 250 calls for the cards I am using.

Ftrace output:

	# perf ftrace --graph-opts depth=100,tail,noirqs -G rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle 0x1: mq | grep \\$
	7) $ 4335849 us  |        } /* mq_init */
	7) $ 4339715 us  |      } /* qdisc_create */
	11) $ 15844438 us |        } /* mq_attach */
	11) $ 16129620 us |      } /* qdisc_graft */
	11) $ 20469368 us |    } /* tc_modify_qdisc */
	11) $ 20470448 us |  } /* rtnetlink_rcv_msg */

	In this case, the rtnetlink_rcv_msg() took 20 seconds, and, while it
	was running, the NIC was not being able to send any packet

Going one step further, this matches what I described above:

	# perf ftrace --graph-opts depth=100,tail,noirqs -G rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle 0x1: mq | grep "\\@\|\\$"

	7) $ 4335849 us  |        } /* mq_init */
	7) $ 4339715 us  |      } /* qdisc_create */
	14) @ 210619.0 us |                      } /* schedule */
	14) @ 210621.3 us |                    } /* schedule_timeout */
	14) @ 210654.0 us |                  } /* wait_for_completion_state */
	14) @ 210716.7 us |                } /* __wait_rcu_gp */
	14) @ 210719.4 us |              } /* synchronize_rcu_normal */
	14) @ 210742.5 us |            } /* synchronize_rcu */
	14) @ 144455.7 us |            } /* __qdisc_destroy */
	14) @ 144458.6 us |          } /* qdisc_put */
	<snip>
	2) @ 131083.6 us |                        } /* schedule */
	2) @ 131086.5 us |                      } /* schedule_timeout */
	2) @ 131129.6 us |                    } /* wait_for_completion_state */
	2) @ 131227.6 us |                  } /* __wait_rcu_gp */
	2) @ 131231.0 us |                } /* synchronize_rcu_normal */
	2) @ 131242.6 us |              } /* synchronize_rcu */
	2) @ 152162.7 us |            } /* __qdisc_destroy */
	2) @ 152165.7 us |          } /* qdisc_put */
	11) $ 15844438 us |        } /* mq_attach */
	11) $ 16129620 us |      } /* qdisc_graft */
	11) $ 20469368 us |    } /* tc_modify_qdisc */
	11) $ 20470448 us |  } /* rtnetlink_rcv_msg */

From the stack trace, it appears that most of the time is spent waiting for the
RCU grace period to free the qdisc (!?):

	static void __qdisc_destroy(struct Qdisc *qdisc)
	{
		if (ops->destroy)
			ops->destroy(qdisc);

		call_rcu(&qdisc->rcu, qdisc_free_cb);
	}

So, from my newbie PoV, the issue can be summarized as follows:

	netdev_lock_ops(dev);
	__tc_modify_qdisc()
	  qdisc_graft()
	    for (i = 0; i <  255; i++)
	      qdisc_put()
	        ____qdisc_destroy()
	          call_rcu()
	      }

Questions: 

1) I assume the egress traffic is blocked because we are modifying the
   qdisc, which makes sense. How is this achieved? Is it related to
   rtnl_lock?

2) Would it be beneficial to attempt qdisc_put() outside of the critical
   section (rtnl_lock?) to prevent this freeze?

Thanks
--breno

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250319-meticulous-succinct-mule-ddabc5%40leitao.
