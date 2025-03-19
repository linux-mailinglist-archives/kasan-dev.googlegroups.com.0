Return-Path: <kasan-dev+bncBDN3ZEGJT4NBBHFE5S7AMGQE5ID2YIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id D14EEA69867
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 19:51:10 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2ff4b130bb2sf7761751a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 11:51:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742410269; cv=pass;
        d=google.com; s=arc-20240605;
        b=UMihN9XPFoYbdX46h/tAkRQ2g+dpFofBbBIkS+BaUH8LefigReWmRFNcekFATqNrht
         bEpcx58gXn2SwDvjPwk/BHgxdeJgo/U3upl67SHO9GFt4VPGslCkqYx6p3nkFGbRc5JH
         qKMDI5oL/8bSdcbcYR+LiZ6snFc/wUngCsFhvFUUlAE8v5LSEdQ/upQuKav6abvi9tV9
         F1r4738h+0RHvINNZIW7MDYzBAd983fGTg2WThOYYxIG6KfRnz78JjDvERdZ5IZrkixE
         fx//fikDvYyfvEIYiwapQPgZU7b0NjND/9W6w7b67q1fEDaPx7Ugz7jX7B4TDpK0Q7Dy
         Qddw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tMwcI/efQOAT0f0uCymvYCrzzx/vs9ZYY0lBRNZMlt8=;
        fh=WwxHndEkCzA6A6KG2zfaMriJ+6H8GqXPIN+7flnxk7Q=;
        b=I66yWYrWZbMpnYTE48vWe/4ULtRikMb7V0ifIZz22RYjMenh1CoIxUbuNN1jXLCtu7
         ZGD+J0Vm+AsoCDu1F03KUAhLuy7gzFalaVuxs+jNPUF6USWnTim05GgJ+P8i0JmRW+0v
         NPO1jwuvrjqPbMVTcgwIUhXTbLhDLwHjfo4bbiwa4ZyFx9CA53eBiL36GRLBHxRIy2ds
         ZqchbFZcYN7POTrTRugWfR92l1lWCeuZ+O2t5/qeIig/aoRCsBtLyNIEdHmLdyIKvQk0
         KyGaXoTcE2vSrwN3lvvp4BwFh8M8dTSna/1knkFiprSheKE64FeL5PVe3vM5bN9vPcJ2
         U6Iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CTyeaedL;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742410269; x=1743015069; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tMwcI/efQOAT0f0uCymvYCrzzx/vs9ZYY0lBRNZMlt8=;
        b=qT9nSL40budq7l5+lxiDzET2NzaAbByBUVjPwx+b1TfKG8fiTWetNemDzdoeh13Ub6
         1sPnzk7XZUuxWTTS59tvxX/Ddqw+v7cFqjW3D4fBVZbCKvZB/ngIR2Vu1gPKJaz7kKQk
         F2qXdQ7bv9OST9vHlx6+mxfW3OSjMwR1rgm3uvOLSGpaxh1GKFHh3/lbNsUY9Yc4UyiI
         MJhKNXIlOHRGhRE6hqSLFgoTIeHc+xZCRLpQ2G9NAoWLvBvpuGIs3c7W5S+6FN+5/U4w
         +zXXpyGCdFCVmfFut2x+I2DDMtAegO1n7LhTzFHSJjngvpANOd+JL3RG7sSSsihqmR/j
         4HiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742410269; x=1743015069;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tMwcI/efQOAT0f0uCymvYCrzzx/vs9ZYY0lBRNZMlt8=;
        b=Qi2SlrJrTbi2wS4gRkFtoPyXWD/zhGX3n/WVIoxlsXCzTaUv3qrR5E+QwHObif3eUB
         1fNjYxhEixGF1aor7nDvPSr2XaxgpfLG+reOP4ixwYo9IVanveNb217XwlF51v4/f3sQ
         3TgFusC6FUSz2l317j/0hW+VEhzlSn4Kxr15gmT0nEgZjKFj1EiD+Lcpfg8MoDUgZdwI
         +w+Cs5MrExKoidV/pFQGgLegCPJntpQeuwVPb7AvR3OZPJGOru7lvg3+4Qy9uBRgVEvq
         dDl/tab6u9yIBdgja80HWYciQ2IsQwlb8VUwr4aYEeDqDCnbSnKMULsU20H1oWMX8Sy9
         XKew==
X-Forwarded-Encrypted: i=2; AJvYcCWTo/FgjFL1aRXsy8FTKNxsLtf358xNe6wPPQZeeU2tm9NGjaLrp2D7a55ZoPZwqdyE9X8sYw==@lfdr.de
X-Gm-Message-State: AOJu0Ywjvr5VVMNblMUiw8BE4tB0PHB/zQeiIt9Ahd1RQ/iQIcUSBVkV
	B3GwLa2lz9Ewa3iSFL+6tyO03T1cRx66I+YvLk0iIacNPA+4Df3Q
X-Google-Smtp-Source: AGHT+IG4GR9zBaTzWtrDQtCvgRPf9akeYXuCwwgHgidQMFfRuJokl3Z7thOa1JdlPPKkaBIiAcpfvg==
X-Received: by 2002:a17:90a:d607:b0:2ff:7b15:813b with SMTP id 98e67ed59e1d1-301d52c311fmr545497a91.17.1742410269125;
        Wed, 19 Mar 2025 11:51:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKBr1bA7UHEvJkot+tzLI+KfgXBci5UxJ/cr8ks9o2Mjw==
Received: by 2002:a17:90b:d85:b0:2f8:3555:13c3 with SMTP id
 98e67ed59e1d1-301d41b3c83ls111514a91.2.-pod-prod-09-us; Wed, 19 Mar 2025
 11:51:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCdsFSGnGKx2NaD9EFbRSvzE10/jxZic86Q/qHKIVdLDmVRqUiLx9DMbWhry8W4/cSoJxNQCIOHw4=@googlegroups.com
X-Received: by 2002:a17:90b:4c12:b0:2f8:b2c:5ef3 with SMTP id 98e67ed59e1d1-301d50b446emr552309a91.14.1742410267795;
        Wed, 19 Mar 2025 11:51:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742410267; cv=none;
        d=google.com; s=arc-20240605;
        b=LDxgrKqviPaGXE4XUXRos3KFGDlaXEmVJ5GqoEDBru43VhjDEt6S/BhKblFdJmftRm
         AOgvVsjKlGepwOw+vqWeZbrRfk5ehpg74dHBTN3oQVFmUVFQOpY360ZZL2OeT10Dm8Cs
         zEH20a/S2PMOyUrs+71302p6tHBPNZQZEc3HsqSC6dHAMYLzt+AJyG4Gt4qLULUq7bnc
         wIOCe43qL5aeQVMm1NDhLNPtaJkWRKtD1pCvKHpq96HWX/NGM8i4+aRTGvmZq6b6RSDA
         8ZA1047X1IMyAZ4HRmnEAv8HdTECn8GWIHRH6kzUuY5Hp3Mq8H75uTPvczFyfdWFYQ9p
         g/tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0xUZScg95dtjsqolj47DWsoNXYRsxRWjDPaCRwJYAFY=;
        fh=WPgnAd+kQP3TKy0cVgehbfihttsA5GvTOskGotnmVS4=;
        b=czXGgv1y0wIrvnQfsTKcfwT4kl9rxVsj9tDeZylYYGmbK7B3BI2e+NQqRQNvyEmq+S
         gNIW5B1ENK74EWM00HX79rZnu+JgVKBXlGpVGZ+7u9FfsNeNmhVHQNY7ITGKyr4i7VIp
         2qrZRv0sUrRDRpZFSrhn+U4ODptlYvYY0IUzGY7XQN7kdzoMB+MtJBxVVlLjAjbGQnht
         1z1QdaRo3yNTlYGnOaX5aLkrh+8hic8wZM+TccRiKDH9/+gZOe5yEoQQCJi9lMelvd1g
         S7FiO0v2TsBhVb9LsvE3V60g5ZMCicmYpV8UpxrZIFs7hpUffPxscHiSB3F5fsdFn1Mp
         UwQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CTyeaedL;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-301a5b7007dsi356024a91.1.2025.03.19.11.51.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Mar 2025 11:51:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id d75a77b69052e-476805acddaso225151cf.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Mar 2025 11:51:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXCsjsSvZC2GpqkYqNAUJsOK956tVz3bh4CacfnJnwWvb8EOSS66bicoa9/lsIxmLlMyqt/p8z43PQ=@googlegroups.com
X-Gm-Gg: ASbGncsfCiInRKrUfA0564kI/ej2Y5qEh0ODUUk/2d03/Yib/RHqQuY40DHMxOgiE4r
	Q6+75g3sUTJPK6f05fRDq1h0/HsUBmHTqgx8/evo+jM1jDAK5NqEkt6cKA2xQYPbJcY52E7KZov
	rjfo5+GqA7nSTvWBTmjHqRWnbEKM4=
X-Received: by 2002:a05:622a:5a93:b0:476:8e3e:2da4 with SMTP id
 d75a77b69052e-47710dd562dmr10808461cf.38.1742410266501; Wed, 19 Mar 2025
 11:51:06 -0700 (PDT)
MIME-Version: 1.0
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
 <20250319-sloppy-active-bonobo-f49d8e@leitao> <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
 <CANn89iKdJfkPrY1rHjzUn5nPbU5Z+VAuW5Le2PraeVuHVQ264g@mail.gmail.com> <CAM_iQpVe+dscK_6hRnTMc_6QjGiBHX0gtaDiwfxggD7tgccbsg@mail.gmail.com>
In-Reply-To: <CAM_iQpVe+dscK_6hRnTMc_6QjGiBHX0gtaDiwfxggD7tgccbsg@mail.gmail.com>
From: "'Eric Dumazet' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Mar 2025 19:50:55 +0100
X-Gm-Features: AQ5f1JoeZEGlqS7UR9UnRwSKfuEAVeEsXx93DzO5LZX85de0PzjjWXVElbyLVLg
Message-ID: <CANn89iKcYa=voGHoX2ODcNMgCEKHRO=-WKiJwCgEZV5-9GV3UQ@mail.gmail.com>
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
To: Cong Wang <xiyou.wangcong@gmail.com>
Cc: paulmck@kernel.org, Breno Leitao <leitao@debian.org>, kuba@kernel.org, 
	jhs@mojatatu.com, jiri@resnulli.us, kuniyu@amazon.com, rcu@vger.kernel.org, 
	kasan-dev@googlegroups.com, netdev@vger.kernel.org
Content-Type: multipart/alternative; boundary="000000000000fd3f530630b680ce"
X-Original-Sender: edumazet@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=CTyeaedL;       spf=pass
 (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::829
 as permitted sender) smtp.mailfrom=edumazet@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Eric Dumazet <edumazet@google.com>
Reply-To: Eric Dumazet <edumazet@google.com>
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

--000000000000fd3f530630b680ce
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 19, 2025 at 7:08=E2=80=AFPM Cong Wang <xiyou.wangcong@gmail.com=
> wrote:

> On Wed, Mar 19, 2025 at 8:08=E2=80=AFAM Eric Dumazet <edumazet@google.com=
> wrote:
> >
> >
> >
> > On Wed, Mar 19, 2025 at 4:04=E2=80=AFPM Paul E. McKenney <paulmck@kerne=
l.org>
> wrote:
> >>
> >> On Wed, Mar 19, 2025 at 07:56:40AM -0700, Breno Leitao wrote:
> >> > On Wed, Mar 19, 2025 at 03:41:37PM +0100, Eric Dumazet wrote:
> >> > > On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao <leitao@debia=
n.org>
> wrote:
> >> > >
> >> > > > Hello,
> >> > > >
> >> > > > I am experiencing an issue with upstream kernel when compiled
> with debug
> >> > > > capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and
> >> > > > CONFIG_LOCKDEP plus a few others. You can find the full
> configuration at
> >> > > > ....
> >> > > >
> >> > > > Basically when running a `tc replace`, it takes 13-20 seconds to
> finish:
> >> > > >
> >> > > >         # time /usr/sbin/tc qdisc replace dev eth0 root handle
> 0x1234: mq
> >> > > >         real    0m13.195s
> >> > > >         user    0m0.001s
> >> > > >         sys     0m2.746s
> >> > > >
> >> > > > While this is running, the machine loses network access
> completely. The
> >> > > > machine's network becomes inaccessible for 13 seconds above,
> which is far
> >> > > > from
> >> > > > ideal.
> >> > > >
> >> > > > Upon investigation, I found that the host is getting stuck in th=
e
> following
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
ca,
> tcm,
> >> > > > &replay);
> >> > > >                 netdev_unlock_ops(dev);
> >> > > >                 ...
> >> > > >         }
> >> > > >
> >> > > > So, the rtnl_lock is held for 13 seconds in the case above. I al=
so
> >> > > > traced that __qdisc_destroy() is called once per NIC queue,
> totalling
> >> > > > a total of 250 calls for the cards I am using.
> >> > > >
> >> > > > Ftrace output:
> >> > > >
> >> > > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> >> > > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root
> handle 0x1: mq
> >> > > > | grep \\$
> >> > > >         7) $ 4335849 us  |        } /* mq_init */
> >> > > >         7) $ 4339715 us  |      } /* qdisc_create */
> >> > > >         11) $ 15844438 us |        } /* mq_attach */
> >> > > >         11) $ 16129620 us |      } /* qdisc_graft */
> >> > > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> >> > > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> >> > > >
> >> > > >         In this case, the rtnetlink_rcv_msg() took 20 seconds,
> and, while
> >> > > > it
> >> > > >         was running, the NIC was not being able to send any pack=
et
> >> > > >
> >> > > > Going one step further, this matches what I described above:
> >> > > >
> >> > > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> >> > > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root
> handle 0x1: mq
> >> > > > | grep "\\@\|\\$"
> >> > > >
> >> > > >         7) $ 4335849 us  |        } /* mq_init */
> >> > > >         7) $ 4339715 us  |      } /* qdisc_create */
> >> > > >         14) @ 210619.0 us |                      } /* schedule *=
/
> >> > > >         14) @ 210621.3 us |                    } /*
> schedule_timeout */
> >> > > >         14) @ 210654.0 us |                  } /*
> >> > > > wait_for_completion_state */
> >> > > >         14) @ 210716.7 us |                } /* __wait_rcu_gp */
> >> > > >         14) @ 210719.4 us |              } /*
> synchronize_rcu_normal */
> >> > > >         14) @ 210742.5 us |            } /* synchronize_rcu */
> >> > > >         14) @ 144455.7 us |            } /* __qdisc_destroy */
> >> > > >         14) @ 144458.6 us |          } /* qdisc_put */
> >> > > >         <snip>
> >> > > >         2) @ 131083.6 us |                        } /* schedule =
*/
> >> > > >         2) @ 131086.5 us |                      } /*
> schedule_timeout */
> >> > > >         2) @ 131129.6 us |                    } /*
> >> > > > wait_for_completion_state */
> >> > > >         2) @ 131227.6 us |                  } /* __wait_rcu_gp *=
/
> >> > > >         2) @ 131231.0 us |                } /*
> synchronize_rcu_normal */
> >> > > >         2) @ 131242.6 us |              } /* synchronize_rcu */
> >> > > >         2) @ 152162.7 us |            } /* __qdisc_destroy */
> >> > > >         2) @ 152165.7 us |          } /* qdisc_put */
> >> > > >         11) $ 15844438 us |        } /* mq_attach */
> >> > > >         11) $ 16129620 us |      } /* qdisc_graft */
> >> > > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> >> > > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> >> > > >
> >> > > > From the stack trace, it appears that most of the time is spent
> waiting
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
> >> > > call_rcu() is asynchronous, this is very different from
> synchronize_rcu().
> >> >
> >> > That is a good point. The offender is synchronize_rcu() is here.
> >>
> >> Should that be synchronize_net()?
> >
> >
> > I think we should redesign lockdep_unregister_key() to work on a
> separately allocated piece of memory,
> > then use kfree_rcu() in it.
> >
> > Ie not embed a "struct lock_class_key" in the struct Qdisc, but a
> pointer to
>
> Lockdep requires the key object must be static:
>

sch->root_lock_key does not seem static to me.


>
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
>
>
You might have misunderstood the code.



> I am afraid the best suggestion here would be just disabling LOCKDEP,
> which is known for big overhead.
>
> Thanks.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANn89iKcYa%3DvoGHoX2ODcNMgCEKHRO%3D-WKiJwCgEZV5-9GV3UQ%40mail.gmail.com.

--000000000000fd3f530630b680ce
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote g=
mail_quote_container"><div dir=3D"ltr" class=3D"gmail_attr">On Wed, Mar 19,=
 2025 at 7:08=E2=80=AFPM Cong Wang &lt;<a href=3D"mailto:xiyou.wangcong@gma=
il.com">xiyou.wangcong@gmail.com</a>&gt; wrote:<br></div><blockquote class=
=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rg=
b(204,204,204);padding-left:1ex">On Wed, Mar 19, 2025 at 8:08=E2=80=AFAM Er=
ic Dumazet &lt;<a href=3D"mailto:edumazet@google.com" target=3D"_blank">edu=
mazet@google.com</a>&gt; wrote:<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt; On Wed, Mar 19, 2025 at 4:04=E2=80=AFPM Paul E. McKenney &lt;<a href=
=3D"mailto:paulmck@kernel.org" target=3D"_blank">paulmck@kernel.org</a>&gt;=
 wrote:<br>
&gt;&gt;<br>
&gt;&gt; On Wed, Mar 19, 2025 at 07:56:40AM -0700, Breno Leitao wrote:<br>
&gt;&gt; &gt; On Wed, Mar 19, 2025 at 03:41:37PM +0100, Eric Dumazet wrote:=
<br>
&gt;&gt; &gt; &gt; On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao &lt=
;<a href=3D"mailto:leitao@debian.org" target=3D"_blank">leitao@debian.org</=
a>&gt; wrote:<br>
&gt;&gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; Hello,<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; I am experiencing an issue with upstream kernel whe=
n compiled with debug<br>
&gt;&gt; &gt; &gt; &gt; capabilities. They are CONFIG_DEBUG_NET, CONFIG_KAS=
AN, and<br>
&gt;&gt; &gt; &gt; &gt; CONFIG_LOCKDEP plus a few others. You can find the =
full configuration at<br>
&gt;&gt; &gt; &gt; &gt; ....<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; Basically when running a `tc replace`, it takes 13-=
20 seconds to finish:<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0# time /usr/sbin/t=
c qdisc replace dev eth0 root handle 0x1234: mq<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0real=C2=A0 =C2=A0 =
0m13.195s<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0user=C2=A0 =C2=A0 =
0m0.001s<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0sys=C2=A0 =C2=A0 =
=C2=A00m2.746s<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; While this is running, the machine loses network ac=
cess completely. The<br>
&gt;&gt; &gt; &gt; &gt; machine&#39;s network becomes inaccessible for 13 s=
econds above, which is far<br>
&gt;&gt; &gt; &gt; &gt; from<br>
&gt;&gt; &gt; &gt; &gt; ideal.<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; Upon investigation, I found that the host is gettin=
g stuck in the following<br>
&gt;&gt; &gt; &gt; &gt; call path:<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0__qdisc_destroy<br=
>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0mq_attach<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0qdisc_graft<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0tc_modify_qdisc<br=
>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0rtnetlink_rcv_msg<=
br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netlink_rcv_skb<br=
>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netlink_unicast<br=
>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netlink_sendmsg<br=
>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; The big offender here is rtnetlink_rcv_msg(), which=
 is called with<br>
&gt;&gt; &gt; &gt; &gt; rtnl_lock<br>
&gt;&gt; &gt; &gt; &gt; in the follow path:<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0static int tc_modi=
fy_qdisc() {<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0...<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0netdev_lock_ops(dev);<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0err =3D __tc_modify_qdisc(skb, n, extack, dev, tca, tcm,<br>
&gt;&gt; &gt; &gt; &gt; &amp;replay);<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0netdev_unlock_ops(dev);<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0...<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0}<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; So, the rtnl_lock is held for 13 seconds in the cas=
e above. I also<br>
&gt;&gt; &gt; &gt; &gt; traced that __qdisc_destroy() is called once per NI=
C queue, totalling<br>
&gt;&gt; &gt; &gt; &gt; a total of 250 calls for the cards I am using.<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; Ftrace output:<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0# perf ftrace --gr=
aph-opts depth=3D100,tail,noirqs -G<br>
&gt;&gt; &gt; &gt; &gt; rtnetlink_rcv_msg=C2=A0 =C2=A0/usr/sbin/tc qdisc re=
place dev eth0 root handle 0x1: mq<br>
&gt;&gt; &gt; &gt; &gt; | grep \\$<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A07) $ 4335849 us=C2=
=A0 |=C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* mq_init */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A07) $ 4339715 us=C2=
=A0 |=C2=A0 =C2=A0 =C2=A0 } /* qdisc_create */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 15844438 us =
|=C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* mq_attach */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 16129620 us =
|=C2=A0 =C2=A0 =C2=A0 } /* qdisc_graft */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 20469368 us =
|=C2=A0 =C2=A0 } /* tc_modify_qdisc */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 20470448 us =
|=C2=A0 } /* rtnetlink_rcv_msg */<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0In this case, the =
rtnetlink_rcv_msg() took 20 seconds, and, while<br>
&gt;&gt; &gt; &gt; &gt; it<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0was running, the N=
IC was not being able to send any packet<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; Going one step further, this matches what I describ=
ed above:<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0# perf ftrace --gr=
aph-opts depth=3D100,tail,noirqs -G<br>
&gt;&gt; &gt; &gt; &gt; rtnetlink_rcv_msg=C2=A0 =C2=A0/usr/sbin/tc qdisc re=
place dev eth0 root handle 0x1: mq<br>
&gt;&gt; &gt; &gt; &gt; | grep &quot;\\@\|\\$&quot;<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A07) $ 4335849 us=C2=
=A0 |=C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* mq_init */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A07) $ 4339715 us=C2=
=A0 |=C2=A0 =C2=A0 =C2=A0 } /* qdisc_create */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210619.0 us =
|=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 } /* schedule */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210621.3 us =
|=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /*=
 schedule_timeout */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210654.0 us =
|=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /*<br>
&gt;&gt; &gt; &gt; &gt; wait_for_completion_state */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210716.7 us =
|=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __wait_rcu_gp=
 */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210719.4 us =
|=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu_norm=
al */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210742.5 us =
|=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 144455.7 us =
|=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __qdisc_destroy */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 144458.6 us =
|=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* qdisc_put */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0&lt;snip&gt;<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131083.6 us |=
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 } /* schedule */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131086.5 us |=
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 } /* schedule_timeout */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131129.6 us |=
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /*<=
br>
&gt;&gt; &gt; &gt; &gt; wait_for_completion_state */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131227.6 us |=
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __wait_=
rcu_gp */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131231.0 us |=
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rc=
u_normal */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131242.6 us |=
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu */<br=
>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 152162.7 us |=
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __qdisc_destroy */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 152165.7 us |=
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* qdisc_put */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 15844438 us =
|=C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* mq_attach */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 16129620 us =
|=C2=A0 =C2=A0 =C2=A0 } /* qdisc_graft */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 20469368 us =
|=C2=A0 =C2=A0 } /* tc_modify_qdisc */<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 20470448 us =
|=C2=A0 } /* rtnetlink_rcv_msg */<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; From the stack trace, it appears that most of the t=
ime is spent waiting<br>
&gt;&gt; &gt; &gt; &gt; for the<br>
&gt;&gt; &gt; &gt; &gt; RCU grace period to free the qdisc (!?):<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0static void __qdis=
c_destroy(struct Qdisc *qdisc)<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0{<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0if (ops-&gt;destroy)<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0ops-&gt;destroy(qdisc);<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0call_rcu(&amp;qdisc-&gt;rcu, qdisc_free_cb);<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; call_rcu() is asynchronous, this is very different from =
synchronize_rcu().<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; That is a good point. The offender is synchronize_rcu() is he=
re.<br>
&gt;&gt;<br>
&gt;&gt; Should that be synchronize_net()?<br>
&gt;<br>
&gt;<br>
&gt; I think we should redesign lockdep_unregister_key() to work on a separ=
ately allocated piece of memory,<br>
&gt; then use kfree_rcu() in it.<br>
&gt;<br>
&gt; Ie not embed a &quot;struct lock_class_key&quot; in the struct Qdisc, =
but a pointer to<br>
<br>
Lockdep requires the key object must be static:<br></blockquote><div><br></=
div><div>sch-&gt;root_lock_key does not seem static to me.</div><div>=C2=A0=
</div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;b=
order-left:1px solid rgb(204,204,204);padding-left:1ex">
<br>
=C2=A0822 /*<br>
=C2=A0823=C2=A0 * Is this the address of a static object:<br>
=C2=A0824=C2=A0 */<br>
=C2=A0825 #ifdef __KERNEL__<br>
=C2=A0826 static int static_obj(const void *obj)<br>
=C2=A0827 {<br>
=C2=A0828=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0unsigned long addr =3D (unsigned=
 long) obj;<br>
=C2=A0829<br>
=C2=A0830=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (is_kernel_core_data(addr))<b=
r>
=C2=A0831=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0retu=
rn 1;<br>
=C2=A0832<br>
=C2=A0833=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0/*<br>
=C2=A0834=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 * keys are allowed in the __ro_=
after_init section.<br>
=C2=A0835=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 */<br>
=C2=A0836=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (is_kernel_rodata(addr))<br>
=C2=A0837=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0retu=
rn 1;<br>
=C2=A0838<br>
<br></blockquote><div><br></div><div>You might have misunderstood the code.=
</div><div><br></div><div>=C2=A0</div><blockquote class=3D"gmail_quote" sty=
le=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);paddi=
ng-left:1ex">
I am afraid the best suggestion here would be just disabling LOCKDEP,<br>
which is known for big overhead.<br>
<br>
Thanks.<br>
</blockquote></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CANn89iKcYa%3DvoGHoX2ODcNMgCEKHRO%3D-WKiJwCgEZV5-9GV3UQ%40mail.gm=
ail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/CANn89iKcYa%3DvoGHoX2ODcNMgCEKHRO%3D-WKiJwCgEZV5-9GV3UQ%40=
mail.gmail.com</a>.<br />

--000000000000fd3f530630b680ce--
