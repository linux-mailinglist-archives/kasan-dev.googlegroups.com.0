Return-Path: <kasan-dev+bncBDN3ZEGJT4NBBL5P5O7AMGQETEJKSJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id ECEFDA68FD2
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 15:41:53 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2ff6167e9ccsf10906967a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 07:41:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742395312; cv=pass;
        d=google.com; s=arc-20240605;
        b=LCHAFGEfjXA7zVoX8aqVSQ5Id35LxOES/1G17mwr84Or7qe52ocfN5iQ9bBvpa4MtI
         3LirwSbClzr/kA8Ks28hYMppct7cei7wGis0joUSokAGoLTK+nezf2XEoVQoBVe1iUYi
         d1D9AuiodFBNp7XUtz1SpglWuIeanvwvE5aXACKxSoBGlociex8+dPWBolBU4ZVKLuHu
         A4+SeOqL5s57HyEFKAo3DdU+xRX0oBM+W2IwYomYcjMOJOQPcFVFtRE7cmxqakEag48D
         w38I2cm0EECeljZ/TA+8bvpsN7UF+U2E0kbkVwrN6li/eNCQ4D0X7RCHLmZydOjxat9L
         CcTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=y786++WfUNk46/Cg6Hv+/WEfnD3vnk3B7aWQqg/yM3Q=;
        fh=EqR7BJCN4AdZlJChlglpY0iAL4echs3yOGjV/UVX95Y=;
        b=grndZCwEhwlxdmRp4PjR592wg1wXhGqO080NJvTEkDt34JMU1PZOplD8nkoMa1AYz1
         xoJoljYZDy0uSdoOeZBzAu5op0HG51Yi1LyIBjXwY59F+gHYAsLuGXPbgH+Hv00fLb0H
         9OHFG5Wr8QxQ2csKpJhrieZuCxeFBolKZFM9M93A7tFcgYkimphB94ICiLhP9reZ6y4y
         sCwbWbo0Jb2qZ/EcNnO2Ra3b9SfOeGHtRrS0WTHq9hdADsaDbWWF9Kk960oPfe6Eu3U/
         pmWc94rTEeHdpb6at4y1LO/D/QKbEnrosuu/CxzSc1i+aLf6HfI1tZWKYZng9oKLcGKj
         cMQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AajfP3Gs;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::82b as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742395312; x=1743000112; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=y786++WfUNk46/Cg6Hv+/WEfnD3vnk3B7aWQqg/yM3Q=;
        b=p6JtU0yTqHi0Bjlcx92UBSf8cqLOOhk2xwGEzja/oAZ0Q88H2K/lWalF/5Rum/yOOf
         8qvFSNlg7FBF0oxovill7HIdgDywHs98CIfo0MjF//RvOSwKK20jlumyaLO1zIXMj9C2
         JyNkjcCr4m4aYEfUus0WPvOWd7NXy9QAyTfbUutyfrPXs/feJ7wiGpt8sC8FBPjWsh6l
         UO9f6gAwZL2bKcrSIx9Ha7z6jxxns+RkMSSIoSNBt7JwoXSk02Ramc953dxkrYXcFlsG
         zL6Kp98wzL1NUXnNVx5Wy6UKM+0F49c5uZvkHZsfNUxX+HSiydrSIAnhGASernm6S9WP
         xYCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742395312; x=1743000112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=y786++WfUNk46/Cg6Hv+/WEfnD3vnk3B7aWQqg/yM3Q=;
        b=iS6OKnDKaOXEzpTpph+SPJ3l+QMYvnoosFOeMvEiPKzUsC5VmccW2FnTBBis7yf7/n
         eejnkkQSBkp07OB6906uSLw4H9tYcONqe3BIjpckEDu8bpy9XM3nrongGRPq3yZNHzFD
         HhWrKejVQy8PvlD/Oza2uyiitLJwgC1LVOHwm49nLwbsFL1eFQbK93qs3xyqph2OwOoV
         kyY6jr53wNsCLHop/S+Nx1hkkznMIiV0OYexfc1YW4Gl41AMIxJkirO7W3viy6h0O6Uv
         KjUrfFBiubiF90X9EVdtXRZZIztDLKBrug86sHUEIOHExNLAc14VWFyDN0/VlubqxehJ
         p2Ow==
X-Forwarded-Encrypted: i=2; AJvYcCWy8AVej+cjnOOXi1Qj3QhpxEYeCC2H7Xgu4hBadOnAJvS1R/6LhzmnMHiaK4ycHkG2gvqN3Q==@lfdr.de
X-Gm-Message-State: AOJu0YyWaYiWVvf8ivxa/BjQk04RkhcD0GKz9Xb3VqVyl48D8CGB8VTS
	ERxc7h70tvGe27KVDWAY5mjWZtS1Mzw6oszNqLVmmoKcWIcEIIEB
X-Google-Smtp-Source: AGHT+IGkNCiBFx7R5A773wrnqRpy2kM3ZyJNXXZYbL9akdpWvzfCNDW+qvJD2jo/GvmRIKNLA6q60g==
X-Received: by 2002:a17:90a:dfc8:b0:2ff:6fc3:79c3 with SMTP id 98e67ed59e1d1-301bde5fc40mr4316353a91.9.1742395311698;
        Wed, 19 Mar 2025 07:41:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALS4njA1DZEkLp0NRoz6U3EDmiZkGe455SlE/jqrbagug==
Received: by 2002:a17:90b:568e:b0:2ef:703f:6f3 with SMTP id
 98e67ed59e1d1-301531d977fls1912740a91.1.-pod-prod-08-us; Wed, 19 Mar 2025
 07:41:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpYcwnX4ebV33fL2cBa4jzGWBawGPiFO4ph9zhm+HQX4aTCHut0Ju0PmV75sx6km0iBniXljbpzhg=@googlegroups.com
X-Received: by 2002:a17:90b:2ed0:b0:2fa:137f:5c61 with SMTP id 98e67ed59e1d1-301bde6210cmr5922072a91.12.1742395310374;
        Wed, 19 Mar 2025 07:41:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742395310; cv=none;
        d=google.com; s=arc-20240605;
        b=M8steOSj34mnVsnMirDDwQJ3hVIFYdS4Sfv1c84TB90ml64i0RsfvuqwFB8ntXl6Pw
         PEx3cWTCdTDcTcO/dzhD/M1yjbWekI6EKMwqusjylkRB89Onm0iIvCsOyWcmzAkfq3GS
         hv8R0yT7TuiNTUwaKlxtpvmupI7NdbQDLq1g3IgW07tyerbY3HdnxPgKikUtvfyKMuUd
         3T31lv6hWEkQJ8okDttkooPW5xt77eigeuBMNLLbkIai13x6LOl39kI7H+BH5AH3slgS
         yI4EKZxkOcOcmlTAi+WDvjDhUMxwq65bRxWxIkFFxRnkUDXlFEMEkOc4Tpk3Om80sexk
         83sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=e3V+TUe0Xxrho6h3R+3CpuPqFqbUArydzIUBypmoHuA=;
        fh=tn9z8YFwJFSTAeeD4PSjMRqTut0vXnrbSCEfGkVHzaI=;
        b=RGPPUxUql/w2GlZJteVX5h9D/wEHB7bKOA+ALE4ec5XdIP01/IwGehNplwvL4ls+Pw
         RdLp8rkDPdf3jL1SwSQ0Ij5pRXMGB8LOsKXHv+LATW8fw+uHRihFtxPxgA/gnfFa7N8r
         aBHpyzHjSrrsKUG2hllEN/1lkgOPLAW4iKnZLevNzFT9Tv537KV+A7AcxLJiLhOW+bQF
         D7tuvnICaZ6EeUbqlDHbkQgSWukDKyaPg4t/UKT9qkKOEcYY2uP/wiB/gpl0I2ZB3VA/
         qmsWxQ3Yu7imTmW+bkIBuu0JQZZyBf5fGbPPDmvko4aRXRbRlGfMLbL0pw2PQrn1ypwD
         Kwgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AajfP3Gs;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::82b as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82b.google.com (mail-qt1-x82b.google.com. [2607:f8b0:4864:20::82b])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-301a39d80fdsi403719a91.0.2025.03.19.07.41.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Mar 2025 07:41:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::82b as permitted sender) client-ip=2607:f8b0:4864:20::82b;
Received: by mail-qt1-x82b.google.com with SMTP id d75a77b69052e-4769f3e19a9so44297731cf.0
        for <kasan-dev@googlegroups.com>; Wed, 19 Mar 2025 07:41:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV99KOLop9pKfS3KcJ79+fAtsmRhShBJ3PSbhnib9LbGF0/JgN1SuiYo1FLVzONsYeBoRoLSTN/Bro=@googlegroups.com
X-Gm-Gg: ASbGncuIJ4BFd1Y8LSK+xPxAtXh26afeIQNwRrvmdZPvHHLUIsPnZhWioCsyorv+DOh
	nqbpSVBVDFMCZkdxGSYx9WpcRlmui1dr2iFvgOZmOotDzvY0ZLN9U91rzCzSC2ZsNa8GLLQEFQH
	LcOoYd7mTy9eKdlYijnVJwSeZfCLs=
X-Received: by 2002:a05:622a:40cb:b0:476:add4:d2ca with SMTP id
 d75a77b69052e-4770830cf06mr41006371cf.24.1742395309124; Wed, 19 Mar 2025
 07:41:49 -0700 (PDT)
MIME-Version: 1.0
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
In-Reply-To: <20250319-meticulous-succinct-mule-ddabc5@leitao>
From: "'Eric Dumazet' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Mar 2025 15:41:37 +0100
X-Gm-Features: AQ5f1JpNmmmt5q_ByrFfGOHx4-dJhmygcKlxflWwKiSwo5loe5IGkPy1YbXVCI0
Message-ID: <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
To: Breno Leitao <leitao@debian.org>
Cc: paulmck@kernel.org, kuba@kernel.org, jhs@mojatatu.com, 
	xiyou.wangcong@gmail.com, jiri@resnulli.us, kuniyu@amazon.com, 
	rcu@vger.kernel.org, kasan-dev@googlegroups.com, netdev@vger.kernel.org
Content-Type: multipart/alternative; boundary="00000000000075ea560630b3054b"
X-Original-Sender: edumazet@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=AajfP3Gs;       spf=pass
 (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::82b
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

--00000000000075ea560630b3054b
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao <leitao@debian.org> wr=
ote:

> Hello,
>
> I am experiencing an issue with upstream kernel when compiled with debug
> capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and
> CONFIG_LOCKDEP plus a few others. You can find the full configuration at
> https://pastebin.com/Dca5EtJv.
>
> Basically when running a `tc replace`, it takes 13-20 seconds to finish:
>
>         # time /usr/sbin/tc qdisc replace dev eth0 root handle 0x1234: mq
>         real    0m13.195s
>         user    0m0.001s
>         sys     0m2.746s
>
> While this is running, the machine loses network access completely. The
> machine's network becomes inaccessible for 13 seconds above, which is far
> from
> ideal.
>
> Upon investigation, I found that the host is getting stuck in the followi=
ng
> call path:
>
>         __qdisc_destroy
>         mq_attach
>         qdisc_graft
>         tc_modify_qdisc
>         rtnetlink_rcv_msg
>         netlink_rcv_skb
>         netlink_unicast
>         netlink_sendmsg
>
> The big offender here is rtnetlink_rcv_msg(), which is called with
> rtnl_lock
> in the follow path:
>
>         static int tc_modify_qdisc() {
>                 ...
>                 netdev_lock_ops(dev);
>                 err =3D __tc_modify_qdisc(skb, n, extack, dev, tca, tcm,
> &replay);
>                 netdev_unlock_ops(dev);
>                 ...
>         }
>
> So, the rtnl_lock is held for 13 seconds in the case above. I also
> traced that __qdisc_destroy() is called once per NIC queue, totalling
> a total of 250 calls for the cards I am using.
>
> Ftrace output:
>
>         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle 0x1: =
mq
> | grep \\$
>         7) $ 4335849 us  |        } /* mq_init */
>         7) $ 4339715 us  |      } /* qdisc_create */
>         11) $ 15844438 us |        } /* mq_attach */
>         11) $ 16129620 us |      } /* qdisc_graft */
>         11) $ 20469368 us |    } /* tc_modify_qdisc */
>         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
>
>         In this case, the rtnetlink_rcv_msg() took 20 seconds, and, while
> it
>         was running, the NIC was not being able to send any packet
>
> Going one step further, this matches what I described above:
>
>         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle 0x1: =
mq
> | grep "\\@\|\\$"
>
>         7) $ 4335849 us  |        } /* mq_init */
>         7) $ 4339715 us  |      } /* qdisc_create */
>         14) @ 210619.0 us |                      } /* schedule */
>         14) @ 210621.3 us |                    } /* schedule_timeout */
>         14) @ 210654.0 us |                  } /*
> wait_for_completion_state */
>         14) @ 210716.7 us |                } /* __wait_rcu_gp */
>         14) @ 210719.4 us |              } /* synchronize_rcu_normal */
>         14) @ 210742.5 us |            } /* synchronize_rcu */
>         14) @ 144455.7 us |            } /* __qdisc_destroy */
>         14) @ 144458.6 us |          } /* qdisc_put */
>         <snip>
>         2) @ 131083.6 us |                        } /* schedule */
>         2) @ 131086.5 us |                      } /* schedule_timeout */
>         2) @ 131129.6 us |                    } /*
> wait_for_completion_state */
>         2) @ 131227.6 us |                  } /* __wait_rcu_gp */
>         2) @ 131231.0 us |                } /* synchronize_rcu_normal */
>         2) @ 131242.6 us |              } /* synchronize_rcu */
>         2) @ 152162.7 us |            } /* __qdisc_destroy */
>         2) @ 152165.7 us |          } /* qdisc_put */
>         11) $ 15844438 us |        } /* mq_attach */
>         11) $ 16129620 us |      } /* qdisc_graft */
>         11) $ 20469368 us |    } /* tc_modify_qdisc */
>         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
>
> From the stack trace, it appears that most of the time is spent waiting
> for the
> RCU grace period to free the qdisc (!?):
>
>         static void __qdisc_destroy(struct Qdisc *qdisc)
>         {
>                 if (ops->destroy)
>                         ops->destroy(qdisc);
>
>                 call_rcu(&qdisc->rcu, qdisc_free_cb);
>

call_rcu() is asynchronous, this is very different from synchronize_rcu().


>         }
>
> So, from my newbie PoV, the issue can be summarized as follows:
>
>         netdev_lock_ops(dev);
>         __tc_modify_qdisc()
>           qdisc_graft()
>             for (i =3D 0; i <  255; i++)
>               qdisc_put()
>                 ____qdisc_destroy()
>                   call_rcu()
>               }
>
> Questions:
>
> 1) I assume the egress traffic is blocked because we are modifying the
>    qdisc, which makes sense. How is this achieved? Is it related to
>    rtnl_lock?
>
> 2) Would it be beneficial to attempt qdisc_put() outside of the critical
>    section (rtnl_lock?) to prevent this freeze?
>
>

It is unclear to me why you have syncrhonize_rcu() calls.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA%40mail.gmail.com.

--00000000000075ea560630b3054b
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote g=
mail_quote_container"><div dir=3D"ltr" class=3D"gmail_attr">On Wed, Mar 19,=
 2025 at 2:09=E2=80=AFPM Breno Leitao &lt;<a href=3D"mailto:leitao@debian.o=
rg">leitao@debian.org</a>&gt; wrote:<br></div><blockquote class=3D"gmail_qu=
ote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,20=
4);padding-left:1ex">Hello,<br>
<br>
I am experiencing an issue with upstream kernel when compiled with debug<br=
>
capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and<br>
CONFIG_LOCKDEP plus a few others. You can find the full configuration at<br=
>
<a href=3D"https://pastebin.com/Dca5EtJv" rel=3D"noreferrer" target=3D"_bla=
nk">https://pastebin.com/Dca5EtJv</a>.<br>
<br>
Basically when running a `tc replace`, it takes 13-20 seconds to finish:<br=
>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 # time /usr/sbin/tc qdisc replace dev eth0 root=
 handle 0x1234: mq<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 real=C2=A0 =C2=A0 0m13.195s<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 user=C2=A0 =C2=A0 0m0.001s<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 sys=C2=A0 =C2=A0 =C2=A00m2.746s<br>
<br>
While this is running, the machine loses network access completely. The<br>
machine&#39;s network becomes inaccessible for 13 seconds above, which is f=
ar from<br>
ideal.<br>
<br>
Upon investigation, I found that the host is getting stuck in the following=
<br>
call path:<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 __qdisc_destroy<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 mq_attach<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 qdisc_graft<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 tc_modify_qdisc<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 rtnetlink_rcv_msg<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 netlink_rcv_skb<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 netlink_unicast<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 netlink_sendmsg<br>
<br>
The big offender here is rtnetlink_rcv_msg(), which is called with rtnl_loc=
k<br>
in the follow path:<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 static int tc_modify_qdisc() {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 ...<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 netdev_lock_ops(dev=
);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 err =3D __tc_modify=
_qdisc(skb, n, extack, dev, tca, tcm, &amp;replay);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 netdev_unlock_ops(d=
ev);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 ...<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
<br>
So, the rtnl_lock is held for 13 seconds in the case above. I also<br>
traced that __qdisc_destroy() is called once per NIC queue, totalling<br>
a total of 250 calls for the cards I am using.<br>
<br>
Ftrace output:<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 # perf ftrace --graph-opts depth=3D100,tail,noi=
rqs -G rtnetlink_rcv_msg=C2=A0 =C2=A0/usr/sbin/tc qdisc replace dev eth0 ro=
ot handle 0x1: mq | grep \\$<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 7) $ 4335849 us=C2=A0 |=C2=A0 =C2=A0 =C2=A0 =C2=
=A0 } /* mq_init */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 7) $ 4339715 us=C2=A0 |=C2=A0 =C2=A0 =C2=A0 } /=
* qdisc_create */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 11) $ 15844438 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
} /* mq_attach */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 11) $ 16129620 us |=C2=A0 =C2=A0 =C2=A0 } /* qd=
isc_graft */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 11) $ 20469368 us |=C2=A0 =C2=A0 } /* tc_modify=
_qdisc */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 11) $ 20470448 us |=C2=A0 } /* rtnetlink_rcv_ms=
g */<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 In this case, the rtnetlink_rcv_msg() took 20 s=
econds, and, while it<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 was running, the NIC was not being able to send=
 any packet<br>
<br>
Going one step further, this matches what I described above:<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 # perf ftrace --graph-opts depth=3D100,tail,noi=
rqs -G rtnetlink_rcv_msg=C2=A0 =C2=A0/usr/sbin/tc qdisc replace dev eth0 ro=
ot handle 0x1: mq | grep &quot;\\@\|\\$&quot;<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 7) $ 4335849 us=C2=A0 |=C2=A0 =C2=A0 =C2=A0 =C2=
=A0 } /* mq_init */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 7) $ 4339715 us=C2=A0 |=C2=A0 =C2=A0 =C2=A0 } /=
* qdisc_create */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 14) @ 210619.0 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* schedule */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 14) @ 210621.3 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* schedule_timeout */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 14) @ 210654.0 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* wait_for_completion_state */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 14) @ 210716.7 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __wait_rcu_gp */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 14) @ 210719.4 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu_normal */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 14) @ 210742.5 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 } /* synchronize_rcu */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 14) @ 144455.7 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 } /* __qdisc_destroy */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 14) @ 144458.6 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 } /* qdisc_put */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 &lt;snip&gt;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 2) @ 131083.6 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* schedule */<br=
>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 2) @ 131086.5 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* schedule_timeout */<b=
r>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 2) @ 131129.6 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* wait_for_completion_state */=
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 2) @ 131227.6 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __wait_rcu_gp */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 2) @ 131231.0 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu_normal */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 2) @ 131242.6 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 2) @ 152162.7 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 } /* __qdisc_destroy */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 2) @ 152165.7 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 } /* qdisc_put */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 11) $ 15844438 us |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
} /* mq_attach */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 11) $ 16129620 us |=C2=A0 =C2=A0 =C2=A0 } /* qd=
isc_graft */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 11) $ 20469368 us |=C2=A0 =C2=A0 } /* tc_modify=
_qdisc */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 11) $ 20470448 us |=C2=A0 } /* rtnetlink_rcv_ms=
g */<br>
<br>
From the stack trace, it appears that most of the time is spent waiting for=
 the<br>
RCU grace period to free the qdisc (!?):<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 static void __qdisc_destroy(struct Qdisc *qdisc=
)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 if (ops-&gt;destroy=
)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 ops-&gt;destroy(qdisc);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 call_rcu(&amp;qdisc=
-&gt;rcu, qdisc_free_cb);<br></blockquote><div><br></div><div>call_rcu() is=
 asynchronous, this is very different from synchronize_rcu().</div><div>=C2=
=A0</div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8e=
x;border-left:1px solid rgb(204,204,204);padding-left:1ex">
=C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
<br>
So, from my newbie PoV, the issue can be summarized as follows:<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 netdev_lock_ops(dev);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 __tc_modify_qdisc()<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 qdisc_graft()<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 for (i =3D 0; i &lt;=C2=A0 255; i=
++)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 qdisc_put()<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 ____qdisc_destroy()=
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 call_rcu()<b=
r>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
<br>
Questions: <br>
<br>
1) I assume the egress traffic is blocked because we are modifying the<br>
=C2=A0 =C2=A0qdisc, which makes sense. How is this achieved? Is it related =
to<br>
=C2=A0 =C2=A0rtnl_lock?<br>
<br>
2) Would it be beneficial to attempt qdisc_put() outside of the critical<br=
>
=C2=A0 =C2=A0section (rtnl_lock?) to prevent this freeze?<br><br></blockquo=
te><div><br></div><div><br></div><div>It is unclear to me=C2=A0why=C2=A0you=
 have syncrhonize_rcu() calls.</div><div><br></div><div><br></div><div><br>=
</div><div>=C2=A0</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA%40mail.gmail.=
com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msg=
id/kasan-dev/CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA%40mail.gma=
il.com</a>.<br />

--00000000000075ea560630b3054b--
