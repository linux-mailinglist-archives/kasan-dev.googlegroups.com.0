Return-Path: <kasan-dev+bncBDTMJ55N44FBBPEU5S7AMGQENE4GHAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E046A697D9
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 19:17:34 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-39131851046sf3301887f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 11:17:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742408253; cv=pass;
        d=google.com; s=arc-20240605;
        b=fW/ZNuOx/Vr2oA01d2nfr0TqUtvHxOrLseWrsxuSgNugRhxrWamxfQRF1Q7DJ8otmw
         t0hBS1C46ddBIXngfVTdtCi9ENtuDYUS4BzmvAOU8tk4kbsKFTtHK5NPMM+qzrpIcKZl
         +t//33zAoyNMEt2kdM1afX/zluk6KT1Gx9JgEyXFe5r4J7XQRwFGH04nVvTzvKjca99+
         /OQhlYv2FfTQEOKB9/BaSIOxEzpkY0ucwYUR36iC9MxNyTGkkn9zqYLhJ6bl/9/3nSxS
         //dPYvpXn1lHZ+ZxISySxyR8RbiIX7vUleQjrwEJvlg5XvXmCzfutB4GZGd0vYiTeQPm
         xQOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=va8+VtBtyGyzdLp7R+cIOL67bluem0LBinnnjmNMYRw=;
        fh=6M6lJOuewRlmbAOF6Wr/nUmMpeDJCdHdvJ++Q4LPegQ=;
        b=ZThRQPlNu0oeJiyg3lv2XC+LWTx1u/VYPg9j06FW+hJXQWu7tH/djQe+a/3TbQZxXM
         m2+3/oaAXNTHhNpFJ6kGMxb6BJP92+ZDUMJJU7ABIhwfCoIGJ9Vh+4kcnQs0S6xTfGBs
         kBl98OPId1JfMQzVPXDU/FkJ3vM7GZ5Yf+oHVZM26Yb4/C8hUcuNXXb01IxOSf/BC9g3
         RY3xIGk5lwTTYY1LZg1/MSYAcehjIKSbFXySCghx1MXAOWCrhpvin1Jy5oBXDbhDPapH
         TRE66lRjEcU8Ir1Q013Q4ThoGHnFI9Lj4fGShZQGS9H+CHjcEWjeR2YbXdPbAQwJiT+J
         HFHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.41 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742408253; x=1743013053; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=va8+VtBtyGyzdLp7R+cIOL67bluem0LBinnnjmNMYRw=;
        b=CNYKVaYmmkfeAXIXSnBR8I0m0mimyGYf6sLVQt7mgWrqsgNIzggofbo9r6llSSrkKR
         0cT8vu+t7bXeuUVk6MnX1R1xSHII54XqfyiW4wA02wOux+J6tc4o8Al94TnbvpNp+R/T
         UBsAaP8G2vIRo8CjTDXAM4GyDJtTlC4M/MlTeSFQhOi1SZr5sb/ZnmfFl5LSbylDKNc4
         HDUOo2wopSJqM1ZKIV7u3qaTjXV77JLCvJdCkTntjO3wIerb/9C4+1zFkmIlr0Wq5/gq
         oglicfcayTam/8A9uR7qFBnH4VYYeBsTm6K6dfchxxAN19fhr1QilRcctViv/mSEqX4C
         HOEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742408253; x=1743013053;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=va8+VtBtyGyzdLp7R+cIOL67bluem0LBinnnjmNMYRw=;
        b=Y7Ycp5xMUE4yv1Cz4qgMO6jom17yv5EgcVVMGp6qkNBcyk5qT5PyrdETvXmyWU/YfM
         yKpUs+wso86s4c5rklFjOKLgSYDSQFIRQq3Jj4mKQruX1/+wA/61jbzDcGTC7H6eensj
         cJHmXivIIuIgItntEx3HU+8bveP1Tu/I/JUKDBJAgAd7vxeaPqwopxTlGYCyVJtW1fci
         NWX6G7S7ExQTvASRd4hPUxT5Iv1nBSRMbbYe+JXqmkD6OG81dL0EEkxolB1KT0B4DsAp
         DHgmlZbYqjIzFnXNQ8XNft1Oml97O8qjQg4gq8lm6AoDGniBxSO+8vBhP/rlG9pDK44E
         4WrQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW5p9cNE9ER431bs7Ae5I6F2CZdE2ro42OhBtPOxLRN55qmsdkEQN8ULKpBe8aRSpW53PxSnA==@lfdr.de
X-Gm-Message-State: AOJu0Yzkz2gE3UrtPPh65k5DDA3d17xtC9QwDjqv/em2pVFW7kWNZqL/
	EUnWZDfj9oL3jUnuhL8dSLWLvICHW0+S2rLqESrXEEWjWi1Y18xy
X-Google-Smtp-Source: AGHT+IGc1HjvUmUPBMOfxvV4+dF2LGszxmew8bbY4t9Tw9vp8ydX7kgvnf0Z0Eo9zzCnt75oTgVcdw==
X-Received: by 2002:a05:6000:1868:b0:391:3207:2e6f with SMTP id ffacd0b85a97d-399795ddfb1mr412264f8f.42.1742408252864;
        Wed, 19 Mar 2025 11:17:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALIBshOeeDWpKUP+K4X69zQSeHMbio+xjBk0knjmPRpSw==
Received: by 2002:a05:6000:1375:b0:38e:dccf:edc2 with SMTP id
 ffacd0b85a97d-399796f8f88ls26787f8f.1.-pod-prod-08-eu; Wed, 19 Mar 2025
 11:17:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvsD6CcwbjBSxuPFMRxfA48+sT79oK5tmTRNWuqc6ONs1dipA239qsZkjy//2WKzeeAXaSvBdgwcU=@googlegroups.com
X-Received: by 2002:a5d:648e:0:b0:391:3cb7:d441 with SMTP id ffacd0b85a97d-399795add2dmr472756f8f.25.1742408250207;
        Wed, 19 Mar 2025 11:17:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742408250; cv=none;
        d=google.com; s=arc-20240605;
        b=XlWzG7T7W9jn5LIMZ8iIkPq80UVh8YrgW6z4wlbt0MbjWWrwe4kyScQaN2aBkMFoTG
         u+0vxrcLkjOS/QRotNsJlLdb6Pk5POKD1d0nG59xS9LmGcVWPbYbvaxJNxnX8AD4oxVb
         RW3Cs0Gu690CEmnR6LZnefFg5vbSn8XM+tFdSSrVOz4+mECNDnH7oCeTh/2jO+vvTKTj
         eTvCLSj1fWJK6DepJO9hwf2xGduXuUeA1kBYQKjMs26ax7wrop1T9HdJOwmWhih7tpTT
         Yk2nliEAXS4v29z5h/L1X/qB7vuXega+kYlSR6BIhol8bixaY+lzvYTaPTH0vWp4Xo6u
         OzXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=uyJYXrZsBVxM/ij0Ri4D7QMFPZ+bXjRXOQyWF1uJXYU=;
        fh=iHJo+n81R7rTcHFJM4CjER00K0QN6Y0ivz+76vibryM=;
        b=JPneifLniF/RI4KsFTg1eKktljWjKk/QC0ZSXc532j8qUEvEaaqBo4H2kfHJlnOiT0
         G2z/LQqvQl9cXDitrgT/zSEauUKGVdsWNIKO5qva+n9LP3d9b3URvdYbfbM/Q6d/qR+w
         3Vi3fNC09KPm7hN3uWqqvOxyYvGMs/ozrRzlPEcRBBBkI3zrzysPWs4Dq+tQzshoDsrb
         oxtzoWrUHNTqK0Z/uJm4VS3lfz6QfeM6jvzIMMiMryjeCbFEQeQpS/+O31SDrH9r1OOs
         TEx15UF9eadbClO+stPrEIv19128e+ltFFV8NKg6yR4RWwRKHZ8uX6NyNkM3qgrve6Xm
         SHfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.41 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ej1-f41.google.com (mail-ej1-f41.google.com. [209.85.218.41])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d43f440c8si543155e9.2.2025.03.19.11.17.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Mar 2025 11:17:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.41 as permitted sender) client-ip=209.85.218.41;
Received: by mail-ej1-f41.google.com with SMTP id a640c23a62f3a-ac2ab99e16eso476954366b.0
        for <kasan-dev@googlegroups.com>; Wed, 19 Mar 2025 11:17:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVFAPlXdo1Cz6vmKvWP11unjjykEE1pGtiYEdbL56C2zqexW2AOi4By/IvR49b1peVSJDJSMxLyJjA=@googlegroups.com
X-Gm-Gg: ASbGncvKOh08pYjZcd2LJqJIcLWzBP5ULNq+3TQFABgNA85JRCv7M4s49tUsfZWKHz3
	t51Lu9WbweD2/McxXwEv18cicTOkhVVc/6d8SzediWgj3y83Xcrz7WfRMXKVieN2yMiW/iGN8jR
	/AxgP5FN6VpYiZvOJLE2ORIjRJFNNN4NZydy5DQ9/n9OdMhoGk0M/w8X0lySwfq5+9IOelENvmj
	Czr7Se9hUfr0eW7+HcRH1NFzivm6cveWvxSk/aFTgkKT16TW8I7PIev2kOOssOj5a2o0rvEhUik
	5gcU0shrDoFE+RENIvF6EB4IHOo1AidwfK44
X-Received: by 2002:a17:906:6a0b:b0:ac1:da09:5d32 with SMTP id a640c23a62f3a-ac3cdf791c2mr61644466b.6.1742408249305;
        Wed, 19 Mar 2025 11:17:29 -0700 (PDT)
Received: from gmail.com ([2a03:2880:30ff:72::])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ac3146aea93sm1040362566b.30.2025.03.19.11.17.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Mar 2025 11:17:28 -0700 (PDT)
Date: Wed, 19 Mar 2025 11:17:26 -0700
From: Breno Leitao <leitao@debian.org>
To: Cong Wang <xiyou.wangcong@gmail.com>
Cc: Eric Dumazet <edumazet@google.com>, paulmck@kernel.org, kuba@kernel.org,
	jhs@mojatatu.com, jiri@resnulli.us, kuniyu@amazon.com,
	rcu@vger.kernel.org, kasan-dev@googlegroups.com,
	netdev@vger.kernel.org
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
Message-ID: <20250319-gifted-mantis-of-persistence-afbb2b@leitao>
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
 <20250319-sloppy-active-bonobo-f49d8e@leitao>
 <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
 <CANn89iKdJfkPrY1rHjzUn5nPbU5Z+VAuW5Le2PraeVuHVQ264g@mail.gmail.com>
 <CAM_iQpVe+dscK_6hRnTMc_6QjGiBHX0gtaDiwfxggD7tgccbsg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAM_iQpVe+dscK_6hRnTMc_6QjGiBHX0gtaDiwfxggD7tgccbsg@mail.gmail.com>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.218.41 as
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

On Wed, Mar 19, 2025 at 11:08:35AM -0700, Cong Wang wrote:
> On Wed, Mar 19, 2025 at 8:08=E2=80=AFAM Eric Dumazet <edumazet@google.com=
> wrote:
> > On Wed, Mar 19, 2025 at 4:04=E2=80=AFPM Paul E. McKenney <paulmck@kerne=
l.org> wrote:
> >>
> >> On Wed, Mar 19, 2025 at 07:56:40AM -0700, Breno Leitao wrote:
> >> > On Wed, Mar 19, 2025 at 03:41:37PM +0100, Eric Dumazet wrote:
> >> > > On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao <leitao@debia=
n.org> wrote:
> >> > >
> >> > > > Hello,
> >> > > >
> >> > > > I am experiencing an issue with upstream kernel when compiled wi=
th debug
> >> > > > capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and
> >> > > > CONFIG_LOCKDEP plus a few others. You can find the full configur=
ation at
> >> > > > ....
> >> > > >
> >> > > > Basically when running a `tc replace`, it takes 13-20 seconds to=
 finish:
> >> > > >
> >> > > >         # time /usr/sbin/tc qdisc replace dev eth0 root handle 0=
x1234: mq
> >> > > >         real    0m13.195s
> >> > > >         user    0m0.001s
> >> > > >         sys     0m2.746s
> >> > > >
> >> > > > While this is running, the machine loses network access complete=
ly. The
> >> > > > machine's network becomes inaccessible for 13 seconds above, whi=
ch is far
> >> > > > from
> >> > > > ideal.
> >> > > >
> >> > > > Upon investigation, I found that the host is getting stuck in th=
e following
> >> > > > call path:
> >> > > >
> >> > > >         __qdisc_destroy
> >> > > >         mq_attach
> >> > > >         qdisc_graft
> >> > > >         tc_modify_qdisc
> >> > > >         rtnetlink_rcv_msg
> >> > > >         netlink_rcv_skb
> >> > > >         netlink_unicast
> >> > > >         netlink_sendmsg
> >> > > >
> >> > > > The big offender here is rtnetlink_rcv_msg(), which is called wi=
th
> >> > > > rtnl_lock
> >> > > > in the follow path:
> >> > > >
> >> > > >         static int tc_modify_qdisc() {
> >> > > >                 ...
> >> > > >                 netdev_lock_ops(dev);
> >> > > >                 err =3D __tc_modify_qdisc(skb, n, extack, dev, t=
ca, tcm,
> >> > > > &replay);
> >> > > >                 netdev_unlock_ops(dev);
> >> > > >                 ...
> >> > > >         }
> >> > > >
> >> > > > So, the rtnl_lock is held for 13 seconds in the case above. I al=
so
> >> > > > traced that __qdisc_destroy() is called once per NIC queue, tota=
lling
> >> > > > a total of 250 calls for the cards I am using.
> >> > > >
> >> > > > Ftrace output:
> >> > > >
> >> > > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> >> > > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root han=
dle 0x1: mq
> >> > > > | grep \\$
> >> > > >         7) $ 4335849 us  |        } /* mq_init */
> >> > > >         7) $ 4339715 us  |      } /* qdisc_create */
> >> > > >         11) $ 15844438 us |        } /* mq_attach */
> >> > > >         11) $ 16129620 us |      } /* qdisc_graft */
> >> > > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> >> > > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> >> > > >
> >> > > >         In this case, the rtnetlink_rcv_msg() took 20 seconds, a=
nd, while
> >> > > > it
> >> > > >         was running, the NIC was not being able to send any pack=
et
> >> > > >
> >> > > > Going one step further, this matches what I described above:
> >> > > >
> >> > > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> >> > > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root han=
dle 0x1: mq
> >> > > > | grep "\\@\|\\$"
> >> > > >
> >> > > >         7) $ 4335849 us  |        } /* mq_init */
> >> > > >         7) $ 4339715 us  |      } /* qdisc_create */
> >> > > >         14) @ 210619.0 us |                      } /* schedule *=
/
> >> > > >         14) @ 210621.3 us |                    } /* schedule_tim=
eout */
> >> > > >         14) @ 210654.0 us |                  } /*
> >> > > > wait_for_completion_state */
> >> > > >         14) @ 210716.7 us |                } /* __wait_rcu_gp */
> >> > > >         14) @ 210719.4 us |              } /* synchronize_rcu_no=
rmal */
> >> > > >         14) @ 210742.5 us |            } /* synchronize_rcu */
> >> > > >         14) @ 144455.7 us |            } /* __qdisc_destroy */
> >> > > >         14) @ 144458.6 us |          } /* qdisc_put */
> >> > > >         <snip>
> >> > > >         2) @ 131083.6 us |                        } /* schedule =
*/
> >> > > >         2) @ 131086.5 us |                      } /* schedule_ti=
meout */
> >> > > >         2) @ 131129.6 us |                    } /*
> >> > > > wait_for_completion_state */
> >> > > >         2) @ 131227.6 us |                  } /* __wait_rcu_gp *=
/
> >> > > >         2) @ 131231.0 us |                } /* synchronize_rcu_n=
ormal */
> >> > > >         2) @ 131242.6 us |              } /* synchronize_rcu */
> >> > > >         2) @ 152162.7 us |            } /* __qdisc_destroy */
> >> > > >         2) @ 152165.7 us |          } /* qdisc_put */
> >> > > >         11) $ 15844438 us |        } /* mq_attach */
> >> > > >         11) $ 16129620 us |      } /* qdisc_graft */
> >> > > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> >> > > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> >> > > >
> >> > > > From the stack trace, it appears that most of the time is spent =
waiting
> >> > > > for the
> >> > > > RCU grace period to free the qdisc (!?):
> >> > > >
> >> > > >         static void __qdisc_destroy(struct Qdisc *qdisc)
> >> > > >         {
> >> > > >                 if (ops->destroy)
> >> > > >                         ops->destroy(qdisc);
> >> > > >
> >> > > >                 call_rcu(&qdisc->rcu, qdisc_free_cb);
> >> > > >
> >> > >
> >> > > call_rcu() is asynchronous, this is very different from synchroniz=
e_rcu().
> >> >
> >> > That is a good point. The offender is synchronize_rcu() is here.
> >>
> >> Should that be synchronize_net()?
> >
> >
> > I think we should redesign lockdep_unregister_key() to work on a separa=
tely allocated piece of memory,
> > then use kfree_rcu() in it.
> >
> > Ie not embed a "struct lock_class_key" in the struct Qdisc, but a point=
er to
>=20
> Lockdep requires the key object must be static:
>=20
>  822 /*
>  823  * Is this the address of a static object:
>  824  */
>  825 #ifdef __KERNEL__
>  826 static int static_obj(const void *obj)
>  827 {
>  828         unsigned long addr =3D (unsigned long) obj;
>  829
>  830         if (is_kernel_core_data(addr))
>  831                 return 1;
>  832
>  833         /*
>  834          * keys are allowed in the __ro_after_init section.
>  835          */
>  836         if (is_kernel_rodata(addr))
>  837                 return 1;
>  838
>=20
> I am afraid the best suggestion here would be just disabling LOCKDEP,
> which is known for big overhead.

This would make lockdep completely useless, I would say. Right now
I have some systems running a "debug kernel", and they work slow, but
fine most of the time. This case is the worst, since the machine loses
network access completely, which triggers a bunch of side effects.

I would suggest having lockdep usable together with network, if
possible.

So, what about having synchronize_rcu_expedited() instead of
synchronize_rcu()?

	https://lore.kernel.org/all/20250319-truthful-whispering-moth-d308b4@leita=
o/

This make having lockdep penaltiy berable again.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250319-gifted-mantis-of-persistence-afbb2b%40leitao.
