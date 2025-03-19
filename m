Return-Path: <kasan-dev+bncBDTMJ55N44FBBM535O7AMGQEFDPSZWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id DC9D8A69256
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 16:07:32 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-5e5c1bb6a23sf925601a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 08:07:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742396852; cv=pass;
        d=google.com; s=arc-20240605;
        b=En6nZDNEuNcg4SOTOuT4Fg5fJv6w6vrfOKgBA7AEr/yVMK8eUInNqZhKPKGmjhgDHt
         9mUlKSttg1SBf/tDPqZT5DIL5JlH9EO9jNimlfcwSIPD3FhV5N5G9M7mFf0LayXEMIOY
         PiJrqtWxMfALb6iOA+lqQqKlj69klaI0zT8xCvJXY+1evLP1quM9sPQCznMr7SEvJdNv
         iUCmJ/ix1Lb5kQ3829LHYT6cVlsy6wK7l/bd4itBX/46a11QqtKiOYxOxhOZa67iQIBt
         drRaTDoyHBJ3SHo7hK4uwgPUY1XEDnm1WkFh9BBSbGOjfKUyLQDvUzdgGbj4ymn2Ef7r
         eQmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=bnIfBoXVXdoRb+KsTvVIKGWZMbG2V6LZCY4Tvt04Csg=;
        fh=fl3cHaCZkgMJIByKH5AI238h/EdkBd7r9c6+kCZpvAo=;
        b=juwCVJKWDKzx1eOsP/WuTP8ui2ATmGUBxTBUt9FUc5k/p1/SQSe+aX150F4OQo5qiK
         /dUV8Bk3WSzi0cDHjSp73ebIjyZZSru5NABNIUzBRGdGsIzigu603v9KsZq7k95t8glc
         iy42BX8cCCU7x3G0nRFUHgFfQJb3nvtn12WQ8+ajC3vdU0peoNgyoEnI7UMOnT8jB59o
         iYU+Lcc06IJ+ucH3A9/93/zpFkGi6FcExaiS/OrwVWiYcBeK8D5jAXcY2QSNhcOIHbML
         ze8gDTOxqE4J6pbxXRQOqzqSbnYTsPHDIO2CjL+C/JzWzjiIWMgQDI4pwyj7iTPIxDqO
         ykWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.54 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742396852; x=1743001652; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bnIfBoXVXdoRb+KsTvVIKGWZMbG2V6LZCY4Tvt04Csg=;
        b=k4f2GvmHnqzlsaLzcBiCvvFOaXEBpjlZOV1YgCtUDsNAMBiuSgvqqjlb2AdVbM10G4
         6ciiCJy0vCb62qw0U9MXpxj/km22CiIGs0RIDhtfOc2Q6vTEsfkEiYprGnO2kr/iarfd
         ewtfaawW8Dawd72caoqG4N9AGuSIx2E6J+X7Sr5LE7StaR/vPtAEf6iCV7Gbc5f01O84
         YgSS++3kqgMgzsSy41+v44SS7Wx67lR5Adi5uqwS09YLn9n+ZYEj75ZvRlsmAp227dEg
         rZnR0ZnJzHuRyd9j8xEwUQzcoEV8PhbpDNoVTXZKvAmm/izXsGpDSvBQ6JoQsAUzI50/
         P4tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742396852; x=1743001652;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bnIfBoXVXdoRb+KsTvVIKGWZMbG2V6LZCY4Tvt04Csg=;
        b=ENvLB+rrmp3wwgKlfD5MW6tq+2tlw7MqKHoZno6Sci6oTsbT/zG3RuSeVAqPGDjUmq
         XbDptRDQ5L7pzkdynvpDXW6f2z5VoKks0GuskX4JXZj7H5DkLr/K3VOtKiUvcyFSfEO3
         Zg9RisQ8UHNXLHOaqmpwolJsAaGO+PKrX96kwXXDyxCTb63ywL3UfnzzkswUPw28yt2C
         +SzazmtiN6biskC7Y5tZ+XUT0nCAkWZn/HuLiyC9D9KPs6LKgPg2k+466rx1zV/l7Fp0
         8IYd50EE2ArhSNVjJehHYd0lTX6um+6FfqOjEaK2+IiBp1kIvzcqIFw0jLwpI3hZqGmn
         kC6A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUourvuxpvhBgqQ9i6ZzN/Hup3JdBdL+O3sDMYSCiXTKBk8tXj2kiOpV7o4o6Ckz/KRG5huBw==@lfdr.de
X-Gm-Message-State: AOJu0YxakZzuj2Euv1/Ov6DE4YWtY0UI9Z3kZ25SDVS2GBbvD/5hQTGj
	HIBKAORlkFOIAsfgxGvXJ/VJ1e8mTasjWaEfv2jt5xvqwLAfRz84
X-Google-Smtp-Source: AGHT+IFVM70tX1rhs8JGmrbSPgJISmUS+04ugQxFU+LR1VSprMlun6fg7pzfA4HIDtQ4g0N2ViGh3Q==
X-Received: by 2002:a05:6402:1cc1:b0:5e0:752a:1c7c with SMTP id 4fb4d7f45d1cf-5eb1efc1b04mr7467128a12.1.1742396851480;
        Wed, 19 Mar 2025 08:07:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIzMHm8aXolhArEn46UgjEAht7oQs2S8B8rtSub2rYWbw==
Received: by 2002:a50:875a:0:b0:5e4:9718:9ea4 with SMTP id 4fb4d7f45d1cf-5eb716c04b2ls305121a12.2.-pod-prod-00-eu;
 Wed, 19 Mar 2025 08:07:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKfKIeXfJYMMMJp8k7C6qL0ndQCzpMj0HzKlLojQlgwvSE0F8wSJu7nHXnxikP/4uTZ+L2tK8VCoQ=@googlegroups.com
X-Received: by 2002:a17:907:60d4:b0:ac2:9a4:700b with SMTP id a640c23a62f3a-ac38f7d129fmr797010866b.16.1742396846374;
        Wed, 19 Mar 2025 08:07:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742396846; cv=none;
        d=google.com; s=arc-20240605;
        b=A0mGSTQIvS4Y5Zf0zYvzq5vVVXBL4n6vWx0CReZopKL+I1HXSa6kyVyfwcvz/94BUR
         jc6ZVA5bZZYpxhqCiapwi58GUsf9/IGf+4xeJDfbKsCVgGd/VbCBvnuvA0w+nkyQGGGw
         HDRSE3IQMTVmRKCQUjnK7h+shwRAYdSfaGgP5MwY2cf4ZJ/OqAC//WHqO6Ob9AOX4kji
         zdazCezuriDfVmlQ0TRmxXdhJc+Ea81EsQZZUeYEuiDX9c3mRswtwAB+AXo5GI8QKR6K
         QrWaW8i3UeBQN5I3UyLkShdpXT2IryfXstFYSPCBc1RCpIQDW2NA9ESKx7FbhBtLStyU
         +KoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=6Vy85hE526l8hFD05fLiRD1Fq4d9FjA+pUAi+u5GdgY=;
        fh=fKw5hus+Ns6cYoomuQKhj9W4Zx9xV4qilDpiEoNzaVE=;
        b=f6Gph0ZYApNon/EJLZyGJlZdTMq1h5D7GDbTHLpi5iwjXowrrz0+kRn/ieNcb/g5uw
         LcIWN+Ff6pOrxVGUSSDboPH7FyDvj2Y4AOEmyQKFDfg6nEmrZT7iD0PBOJKOHMXo+w1j
         NLWPUbS+kmkPXYLUrc0opaxyyrYH8ykA9zjXggvZlAmJaQi6yOmAY6iezpZqPuzRKd+c
         NFkVSijNhmspxC843oTrpiymAk8EyVeM85IPo0YhO1H3bheovv4h8O9e5siEp+28nVbM
         c11QZ9yy9mabGozAf4hZ4B9TUSFUW/tzztFwQs795RVlljVBnfTqlrmFzR3dOmwDqkuc
         yidQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.54 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ej1-f54.google.com (mail-ej1-f54.google.com. [209.85.218.54])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5e816ada5c5si426718a12.4.2025.03.19.08.07.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Mar 2025 08:07:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.54 as permitted sender) client-ip=209.85.218.54;
Received: by mail-ej1-f54.google.com with SMTP id a640c23a62f3a-ac2a089fbbdso158206566b.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Mar 2025 08:07:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWrYyj1fvDl0UzfDcPAfnjlVCxQIdUI9ph/3ecr6JxTpqtoKf504eFCQR1W/9Cmp83rhtN49+XfQCY=@googlegroups.com
X-Gm-Gg: ASbGnctcYQxHIpo0cxXz+6NN15iXbhQKjXUh2OwPsMX/ph7Y9UaOkmwLIKQ862uekvs
	0IYVTePnNYnln2H/FUcSSb+f6YsTcsnQNSin2snqyHdZtE8uIvuGjHzJMfAymoj2KTjIztehGAU
	FLlI8l+/lppw1q4rMpSZDRwY3xJAfQ4H2bbdme0VEuBJTZQ+wjnAOWpJ0WQiBIroh75BHk8P1e7
	1Hbe8y98uV1EBbJjoSblJSJXC7xbIajrNFXHkSGWqEmOqzikIdWNsSnm6STu/BM4QaKXqU7Oq0k
	4uyJN4dMC5+3LMhch6UtpMNT+S0d6opd37SQ
X-Received: by 2002:a17:907:ba0c:b0:ac1:e45f:9c71 with SMTP id a640c23a62f3a-ac3b6abe719mr325683666b.1.1742396839326;
        Wed, 19 Mar 2025 08:07:19 -0700 (PDT)
Received: from gmail.com ([2a03:2880:30ff:70::])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ac314a47f0bsm1012703466b.157.2025.03.19.08.07.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Mar 2025 08:07:18 -0700 (PDT)
Date: Wed, 19 Mar 2025 08:07:16 -0700
From: Breno Leitao <leitao@debian.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Eric Dumazet <edumazet@google.com>, kuba@kernel.org, jhs@mojatatu.com,
	xiyou.wangcong@gmail.com, jiri@resnulli.us, kuniyu@amazon.com,
	rcu@vger.kernel.org, kasan-dev@googlegroups.com,
	netdev@vger.kernel.org
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
Message-ID: <20250319-radical-cornflower-labrador-b49bfe@leitao>
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
 <20250319-sloppy-active-bonobo-f49d8e@leitao>
 <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.218.54 as
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

Hello Paul,

On Wed, Mar 19, 2025 at 08:04:52AM -0700, Paul E. McKenney wrote:
> On Wed, Mar 19, 2025 at 07:56:40AM -0700, Breno Leitao wrote:
> > On Wed, Mar 19, 2025 at 03:41:37PM +0100, Eric Dumazet wrote:
> > > On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao <leitao@debian.o=
rg> wrote:
> > >=20
> > > > Hello,
> > > >
> > > > I am experiencing an issue with upstream kernel when compiled with =
debug
> > > > capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and
> > > > CONFIG_LOCKDEP plus a few others. You can find the full configurati=
on at
> > > > ....
> > > >
> > > > Basically when running a `tc replace`, it takes 13-20 seconds to fi=
nish:
> > > >
> > > >         # time /usr/sbin/tc qdisc replace dev eth0 root handle 0x12=
34: mq
> > > >         real    0m13.195s
> > > >         user    0m0.001s
> > > >         sys     0m2.746s
> > > >
> > > > While this is running, the machine loses network access completely.=
 The
> > > > machine's network becomes inaccessible for 13 seconds above, which =
is far
> > > > from
> > > > ideal.
> > > >
> > > > Upon investigation, I found that the host is getting stuck in the f=
ollowing
> > > > call path:
> > > >
> > > >         __qdisc_destroy
> > > >         mq_attach
> > > >         qdisc_graft
> > > >         tc_modify_qdisc
> > > >         rtnetlink_rcv_msg
> > > >         netlink_rcv_skb
> > > >         netlink_unicast
> > > >         netlink_sendmsg
> > > >
> > > > The big offender here is rtnetlink_rcv_msg(), which is called with
> > > > rtnl_lock
> > > > in the follow path:
> > > >
> > > >         static int tc_modify_qdisc() {
> > > >                 ...
> > > >                 netdev_lock_ops(dev);
> > > >                 err =3D __tc_modify_qdisc(skb, n, extack, dev, tca,=
 tcm,
> > > > &replay);
> > > >                 netdev_unlock_ops(dev);
> > > >                 ...
> > > >         }
> > > >
> > > > So, the rtnl_lock is held for 13 seconds in the case above. I also
> > > > traced that __qdisc_destroy() is called once per NIC queue, totalli=
ng
> > > > a total of 250 calls for the cards I am using.
> > > >
> > > > Ftrace output:
> > > >
> > > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> > > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle=
 0x1: mq
> > > > | grep \\$
> > > >         7) $ 4335849 us  |        } /* mq_init */
> > > >         7) $ 4339715 us  |      } /* qdisc_create */
> > > >         11) $ 15844438 us |        } /* mq_attach */
> > > >         11) $ 16129620 us |      } /* qdisc_graft */
> > > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> > > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> > > >
> > > >         In this case, the rtnetlink_rcv_msg() took 20 seconds, and,=
 while
> > > > it
> > > >         was running, the NIC was not being able to send any packet
> > > >
> > > > Going one step further, this matches what I described above:
> > > >
> > > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> > > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle=
 0x1: mq
> > > > | grep "\\@\|\\$"
> > > >
> > > >         7) $ 4335849 us  |        } /* mq_init */
> > > >         7) $ 4339715 us  |      } /* qdisc_create */
> > > >         14) @ 210619.0 us |                      } /* schedule */
> > > >         14) @ 210621.3 us |                    } /* schedule_timeou=
t */
> > > >         14) @ 210654.0 us |                  } /*
> > > > wait_for_completion_state */
> > > >         14) @ 210716.7 us |                } /* __wait_rcu_gp */
> > > >         14) @ 210719.4 us |              } /* synchronize_rcu_norma=
l */
> > > >         14) @ 210742.5 us |            } /* synchronize_rcu */
> > > >         14) @ 144455.7 us |            } /* __qdisc_destroy */
> > > >         14) @ 144458.6 us |          } /* qdisc_put */
> > > >         <snip>
> > > >         2) @ 131083.6 us |                        } /* schedule */
> > > >         2) @ 131086.5 us |                      } /* schedule_timeo=
ut */
> > > >         2) @ 131129.6 us |                    } /*
> > > > wait_for_completion_state */
> > > >         2) @ 131227.6 us |                  } /* __wait_rcu_gp */
> > > >         2) @ 131231.0 us |                } /* synchronize_rcu_norm=
al */
> > > >         2) @ 131242.6 us |              } /* synchronize_rcu */
> > > >         2) @ 152162.7 us |            } /* __qdisc_destroy */
> > > >         2) @ 152165.7 us |          } /* qdisc_put */
> > > >         11) $ 15844438 us |        } /* mq_attach */
> > > >         11) $ 16129620 us |      } /* qdisc_graft */
> > > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> > > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> > > >
> > > > From the stack trace, it appears that most of the time is spent wai=
ting
> > > > for the
> > > > RCU grace period to free the qdisc (!?):
> > > >
> > > >         static void __qdisc_destroy(struct Qdisc *qdisc)
> > > >         {
> > > >                 if (ops->destroy)
> > > >                         ops->destroy(qdisc);
> > > >
> > > >                 call_rcu(&qdisc->rcu, qdisc_free_cb);
> > > >
> > >=20
> > > call_rcu() is asynchronous, this is very different from synchronize_r=
cu().
> >=20
> > That is a good point. The offender is synchronize_rcu() is here.
>=20
> Should that be synchronize_net()?

It seems to be coming from here, Paul:

       __qdisc_destroy() {
               lockdep_unregister_key(&qdisc->root_lock_key) {
                       ...
                       /* Wait until is_dynamic_key() has finished accessin=
g k->hash_entry. */
                       synchronize_rcu();

I suppose one option is to convert it into a call_rcu() !?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250319-radical-cornflower-labrador-b49bfe%40leitao.
