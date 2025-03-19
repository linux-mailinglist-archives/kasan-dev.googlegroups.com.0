Return-Path: <kasan-dev+bncBDTMJ55N44FBBLVW5O7AMGQEVGU4A7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id C823DA691B2
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 15:56:48 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-43bd0586a73sf28554805e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 07:56:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742396208; cv=pass;
        d=google.com; s=arc-20240605;
        b=IDeMHwrzXa60/4xM1jOC2iqH//WtY+wZzSLo7iYzz6W86m4UGif9JXWKrNGvjijPG9
         pBn47TH/eVfa+NFazjiIzDb9cj5WYCm+PosVYQyo95ldWD3D6gA5JBRJBbEOlL8mXE+X
         L3D0mIjE12SLS5u6HutaydGbGd+byoeMx2pLlKK6tYbzRLS6nwHQhHOpLp1U+vrPMGaB
         Sh9olT6V2Axr8j+1sMI7asl+GTgmXeIFrB/UZfjhAmHnG6QOzlZD98ykjBh4Kn7lGkDE
         fXdxwBB3O1bXAeCBO9ZkQrssR4tgbeuA0Wc1vANPr1zxgRQDpUyloreGElrt3AYD2dfi
         472w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=di0az47pZuR+cCRlr8wb6xQZhzDGuS4Jy6DJBVjgwM4=;
        fh=PGoJPJq5sYkF8ZMjYnN+t3YhMMB6djnVMBk3RTU51b4=;
        b=SXgY3MZEVDtlBKmPI9SEeXuhpln6JkldpQNkyX8rpRNR/NMyUkWGecD9iU61CSJ+JZ
         saYGxceL1AoNaVgsmF784x3vva6TTZhg+Khwa3Qa00IBjzcc/KpxvCMklN12r3QOj308
         Pl2mTWSQy2tpMSHO34uX5/OjVWz01jKLyloEeGlLnyfOoZgJ7N1gMkZN9dh0BXT7oG+0
         dG+ULOEMyhXUeC4HU1olY1XBtPhgee0YY7PrYjyX2Duepta4SRS1IExeEtgmioFnR5YH
         SGjKjID9LKc097GpYP2+V5utDrqGfn6/KZjMowfwAVfe1VWpXrIfu61UMQc1OMap7/bm
         saCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.48 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742396208; x=1743001008; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=di0az47pZuR+cCRlr8wb6xQZhzDGuS4Jy6DJBVjgwM4=;
        b=SHCNF6kFbd7m/H25lkyqtQkcgj6Hq/jH/uY4ost21710G7y4JENSYU6T814pJ5e/JE
         MGXLrS/3i/YnbLO2cT/xVwNllaxgy5oQFlbbO1tu3D/Cx3Lxsjc1K4By/L/KTBC7oIFz
         RKm84QkMqc1jUNqrXfo7HVcR6ydp1uKrbh/kXUW29MdslDBlxJbQ5SN0qnsORoHL8/GJ
         E2aHrX3aQw0HGcdv3Zf5N196iNKjxYWZkMsOFRfhyQlZvLRBpAYmEa79MH3M+9drXtnA
         L3rIyCmhiv9qaWBRSjkZd0IrDiS311K17oQhc+eoU9/SB21RlAWRXwJprMWbcQtqbrkk
         mx1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742396208; x=1743001008;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=di0az47pZuR+cCRlr8wb6xQZhzDGuS4Jy6DJBVjgwM4=;
        b=TK7DIybdkJGSXprxJPEkEAQMjfM6utUcWFTG55jzyzruS66eBb+Aqv7xQuWEZJHcJV
         WFlkvzBBlYKsJ81eqwsSj3a0ePpMVHJk6rY9BaH1do+kIjq35wKSs45RGYlnvWOiBcA3
         th7tvdpG86O0fpeMMp32cwQudwV7WjlpQnzF1Dtk+P486rNAUVii8txUhcTFEmF/HSME
         GCkP07eoatmhVy8XDwRvZfAeK84kniofQwWVwSKE48uGypktjS9LcUCjwqmPCxaVT+gc
         Gu+Qsw18W3a0EJu/iVtnI7ZxRsVKul8RYLJfScFmhsXBgz2PrYcKzyT7BxwBjOj3jzXI
         5d9Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU6k9r5MN4tff2ShRT6UbwKRcBnl5WgnqqT/Wp8X32fC+fnVuQQQLDgqJh1tX/rgRg0Bjd02g==@lfdr.de
X-Gm-Message-State: AOJu0Yw6+jDWp+SrMkQy8HvrJMYYmNgS1MPC0SX0KpQtN8Sa0VekGlnZ
	vElPBM1ceG78hVUqDHQnBbFthqNgxe6m//B1No+GLe26W2yidh+S
X-Google-Smtp-Source: AGHT+IER8u8Mrlkrr5GCFO+lZF9EvxlfZBymgD35HyNRKGKM7R3u8a+DJU03KoYTzESiJCJB+565AA==
X-Received: by 2002:a05:600c:1991:b0:43d:1f1:8cd with SMTP id 5b1f17b1804b1-43d438691ecmr17417705e9.24.1742396207460;
        Wed, 19 Mar 2025 07:56:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIkNEvUF/IPYtgDeVSYUeqfiLIDjys5zBEVl2IU9tzTMQ==
Received: by 2002:a05:600c:56c8:b0:43d:17c2:e7f1 with SMTP id
 5b1f17b1804b1-43d1fc0e79als2921685e9.2.-pod-prod-05-eu; Wed, 19 Mar 2025
 07:56:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXVxDttbo1ORC2Xvvieyb3Ur3ce5hiwHNO0GaYZB7MOpF7JNJW98ZW9pzL0AflnB9XNVB2kn/sVVnM=@googlegroups.com
X-Received: by 2002:a05:600c:3490:b0:43d:1b74:e89a with SMTP id 5b1f17b1804b1-43d4379395amr28546715e9.9.1742396204631;
        Wed, 19 Mar 2025 07:56:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742396204; cv=none;
        d=google.com; s=arc-20240605;
        b=b2NO44RD6IZHLKMoe5C0kvLR1l9GW5SrDZEnv9RrNMGR5w1gLY83n+txIL5u6rS1NF
         IAs8yBzYWUK+gkM/yWwhmxJNpTCHKtKkpxebDWpbGPwO9Sx24t29XYS+Fz90WBB4sthF
         E3YAw6pGtc/oFO0Fa+IkMPLjodCYEzWKHQOU1beX5IRnS/aHv+hp+53D5DjkicK0FYNT
         AkPj2IkmpUIIVL8w6aVAsow1Etwzrnuw/GgAKVsDpNML4NtOOhWLVBHaWMDDmcGmVPtS
         kjntnLoiiv9eb1y2joqVzF3ThyRB1VKTuXBcGvPLIdOrqsmL387MOsrHgr0JTpPeuQCB
         wYdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=UoqPjEmwm2kureJLm1BvhPmdE3mSFYuoN4uUvhBD2O4=;
        fh=B8Hrn3ycZBCB1+ujBcXOz3lYsQLy8qI5JgSP2BI8FMo=;
        b=dCktcV3HEuil2cIAdWpQq9C/zbi9nIKPPjYAaR82ibaP3B0CR7TQSJsM/MNmX6UWhy
         yI3ZdzBbA3LcFTOt7k7GiGSIz484Hp4nBL8CMpWZqfd2J55VRWxnKp+j5u8rch8pprK+
         nJxZwtRMQazuSRMOGYpr5zo9ZiEfna4uMGzpbAYPABvvD9u1VTRwU5eefqb5OkZuIUw3
         krWHHlWIPmV0a6KHivtCZuhIcShkuyK0qVZSSb2Ge17tXoOAZ55QBT+EzfLIuCJXHivN
         IaFZ9B9BHGZazyIC+50/Ig+CrugR0MLWA92PrPVXCXCMiSxJNqaaEfuO3X7LZ77x8Qvr
         28qg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.48 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ej1-f48.google.com (mail-ej1-f48.google.com. [209.85.218.48])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d43f4753bsi201145e9.1.2025.03.19.07.56.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Mar 2025 07:56:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.48 as permitted sender) client-ip=209.85.218.48;
Received: by mail-ej1-f48.google.com with SMTP id a640c23a62f3a-ac2963dc379so1185997466b.2
        for <kasan-dev@googlegroups.com>; Wed, 19 Mar 2025 07:56:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXZeeuG596sQojAgsr31to9BuLola608eE4urwefSgmA6VQSdj9H3BJ7I+2WWVK41QKIJClCduDqSA=@googlegroups.com
X-Gm-Gg: ASbGnct46WDedgRcgWFC6dwgVXpYNXwouScR0KZXtnydCEJKpoy7k5Vuoc814JEP8Rk
	zAIitU6vOG+dtTWfIynb9QAa0XxRTkDH9IbZ5JGXkkFdxqPK6i9wcbvG9EkSB9qZPzYMPi/nyOQ
	DvtU4FnilOyj9quujXLErgYH6AAT8slOWE7bBxKPWhNLuPw3Cu/RZkT83FItcmvXvrxlhu5v+Hn
	LXqInOAPQJqGI5bqxFM8eeVDoEFtePNr6o40wl1oT6O3aHxz6qItzR6Eo6038xMgMLcZaeLdE/1
	6Ip21Mrv0cxy7eZ2sL0Y16e2R+xW7CU3DWOM
X-Received: by 2002:a17:906:ee89:b0:abe:f48c:bcd with SMTP id a640c23a62f3a-ac3b7f78b4bmr285916166b.50.1742396203734;
        Wed, 19 Mar 2025 07:56:43 -0700 (PDT)
Received: from gmail.com ([2a03:2880:30ff:71::])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ac31485d03bsm1018904766b.82.2025.03.19.07.56.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Mar 2025 07:56:43 -0700 (PDT)
Date: Wed, 19 Mar 2025 07:56:40 -0700
From: Breno Leitao <leitao@debian.org>
To: Eric Dumazet <edumazet@google.com>
Cc: paulmck@kernel.org, kuba@kernel.org, jhs@mojatatu.com,
	xiyou.wangcong@gmail.com, jiri@resnulli.us, kuniyu@amazon.com,
	rcu@vger.kernel.org, kasan-dev@googlegroups.com,
	netdev@vger.kernel.org
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
Message-ID: <20250319-sloppy-active-bonobo-f49d8e@leitao>
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.218.48 as
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

On Wed, Mar 19, 2025 at 03:41:37PM +0100, Eric Dumazet wrote:
> On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao <leitao@debian.org> =
wrote:
>=20
> > Hello,
> >
> > I am experiencing an issue with upstream kernel when compiled with debu=
g
> > capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and
> > CONFIG_LOCKDEP plus a few others. You can find the full configuration a=
t
> > ....
> >
> > Basically when running a `tc replace`, it takes 13-20 seconds to finish=
:
> >
> >         # time /usr/sbin/tc qdisc replace dev eth0 root handle 0x1234: =
mq
> >         real    0m13.195s
> >         user    0m0.001s
> >         sys     0m2.746s
> >
> > While this is running, the machine loses network access completely. The
> > machine's network becomes inaccessible for 13 seconds above, which is f=
ar
> > from
> > ideal.
> >
> > Upon investigation, I found that the host is getting stuck in the follo=
wing
> > call path:
> >
> >         __qdisc_destroy
> >         mq_attach
> >         qdisc_graft
> >         tc_modify_qdisc
> >         rtnetlink_rcv_msg
> >         netlink_rcv_skb
> >         netlink_unicast
> >         netlink_sendmsg
> >
> > The big offender here is rtnetlink_rcv_msg(), which is called with
> > rtnl_lock
> > in the follow path:
> >
> >         static int tc_modify_qdisc() {
> >                 ...
> >                 netdev_lock_ops(dev);
> >                 err =3D __tc_modify_qdisc(skb, n, extack, dev, tca, tcm=
,
> > &replay);
> >                 netdev_unlock_ops(dev);
> >                 ...
> >         }
> >
> > So, the rtnl_lock is held for 13 seconds in the case above. I also
> > traced that __qdisc_destroy() is called once per NIC queue, totalling
> > a total of 250 calls for the cards I am using.
> >
> > Ftrace output:
> >
> >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle 0x1=
: mq
> > | grep \\$
> >         7) $ 4335849 us  |        } /* mq_init */
> >         7) $ 4339715 us  |      } /* qdisc_create */
> >         11) $ 15844438 us |        } /* mq_attach */
> >         11) $ 16129620 us |      } /* qdisc_graft */
> >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> >
> >         In this case, the rtnetlink_rcv_msg() took 20 seconds, and, whi=
le
> > it
> >         was running, the NIC was not being able to send any packet
> >
> > Going one step further, this matches what I described above:
> >
> >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle 0x1=
: mq
> > | grep "\\@\|\\$"
> >
> >         7) $ 4335849 us  |        } /* mq_init */
> >         7) $ 4339715 us  |      } /* qdisc_create */
> >         14) @ 210619.0 us |                      } /* schedule */
> >         14) @ 210621.3 us |                    } /* schedule_timeout */
> >         14) @ 210654.0 us |                  } /*
> > wait_for_completion_state */
> >         14) @ 210716.7 us |                } /* __wait_rcu_gp */
> >         14) @ 210719.4 us |              } /* synchronize_rcu_normal */
> >         14) @ 210742.5 us |            } /* synchronize_rcu */
> >         14) @ 144455.7 us |            } /* __qdisc_destroy */
> >         14) @ 144458.6 us |          } /* qdisc_put */
> >         <snip>
> >         2) @ 131083.6 us |                        } /* schedule */
> >         2) @ 131086.5 us |                      } /* schedule_timeout *=
/
> >         2) @ 131129.6 us |                    } /*
> > wait_for_completion_state */
> >         2) @ 131227.6 us |                  } /* __wait_rcu_gp */
> >         2) @ 131231.0 us |                } /* synchronize_rcu_normal *=
/
> >         2) @ 131242.6 us |              } /* synchronize_rcu */
> >         2) @ 152162.7 us |            } /* __qdisc_destroy */
> >         2) @ 152165.7 us |          } /* qdisc_put */
> >         11) $ 15844438 us |        } /* mq_attach */
> >         11) $ 16129620 us |      } /* qdisc_graft */
> >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> >
> > From the stack trace, it appears that most of the time is spent waiting
> > for the
> > RCU grace period to free the qdisc (!?):
> >
> >         static void __qdisc_destroy(struct Qdisc *qdisc)
> >         {
> >                 if (ops->destroy)
> >                         ops->destroy(qdisc);
> >
> >                 call_rcu(&qdisc->rcu, qdisc_free_cb);
> >
>=20
> call_rcu() is asynchronous, this is very different from synchronize_rcu()=
.

That is a good point. The offender is synchronize_rcu() is here.
>=20
>=20
> >         }
> >
> > So, from my newbie PoV, the issue can be summarized as follows:
> >
> >         netdev_lock_ops(dev);
> >         __tc_modify_qdisc()
> >           qdisc_graft()
> >             for (i =3D 0; i <  255; i++)
> >               qdisc_put()
> >                 ____qdisc_destroy()
> >                   call_rcu()
> >               }
> >
> > Questions:
> >
> > 1) I assume the egress traffic is blocked because we are modifying the
> >    qdisc, which makes sense. How is this achieved? Is it related to
> >    rtnl_lock?
> >
> > 2) Would it be beneficial to attempt qdisc_put() outside of the critica=
l
> >    section (rtnl_lock?) to prevent this freeze?
> >
> >
>=20
> It is unclear to me why you have syncrhonize_rcu() calls.

This is coming from:

	__qdisc_destroy() {
		lockdep_unregister_key(&qdisc->root_lock_key) {
			...
			/* Wait until is_dynamic_key() has finished accessing k->hash_entry. */
			synchronize_rcu();

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250319-sloppy-active-bonobo-f49d8e%40leitao.
