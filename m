Return-Path: <kasan-dev+bncBDN3ZEGJT4NBB4NX5O7AMGQEUZTPUTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D3806A691FF
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 16:00:03 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3ce843b51c3sf191442975ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 08:00:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742396401; cv=pass;
        d=google.com; s=arc-20240605;
        b=OY0ffo9leSQGA+KPk5JGmFEgH3BVmtx+0Ks52s9JqEN8F7sLP638KJtUoKQgto+zQK
         dtz6tzT+VUbbbE9W59682yBPxOEaMAPwk74V6aW56ZYW+S5FhpbWKlIF8VTImJTeskyZ
         kJ0daZNjGQ5TepGOFWZ36SoLuGfdMv5GLuI2Ci5SDpSn39RUyQ00VfuCOZlkKoahg+Pd
         KNbkrIvOiwsDDhSWNMVo1YulgIHJXwfYZTggFkoWXi5qGW+LWzbTkHM5mhyvfZUCpd8b
         O90RWyW8N7ary3s90mKjqZlzLviGc8pkt+eNoY7a7MBZN90rb6KMMXAT9Mdooq60Le0d
         dGPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JJbiTGrPF2TdW0St71byyZQG2FKeePQSTcDcIjDX3Pc=;
        fh=mb5HSvMahveZYvCD/iyHbO/E3Vpv9pUElrg9Opb0jwo=;
        b=QMpLAvnS3ZwbMe8Ma7j9JdfWeJHrfpTwA2oUgv2zXsO0gzJFZsx0asBg75LVMIAlaZ
         kLJfoC/o9EAiUDu5IttBz5PzLEst5ub4YfpHK1svFk2S63XSeCLiIzra1jpfRkJacoAO
         cUuUlB4bBvS3gaNuHfOxQSh8O0i5VgPGNCtB3vdLXYh6ScYjsVMIphzKqI2H/+LW6c8X
         l8CEp966l2xwJ02jHKIyrCc1hFjwa8m8fS7BZUHwiWceQefCQt+xs2P3prnOBSDGdnhJ
         ykib+h+TRWvVFeQFGvU5S/CkibvhL8d01rrYqcSy6Dj9rVmeSBFPcN1d5jXb5C/d9tie
         FL6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TXNJueGA;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742396401; x=1743001201; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JJbiTGrPF2TdW0St71byyZQG2FKeePQSTcDcIjDX3Pc=;
        b=ILtNSdp8ojrTWiXcb+UHc2JDy7MJfSrrpawTjv9l9YUVnqSfTSXUIIJqZqE5Z5O0VL
         Li/hCWiPdhX9nV00it1EBSoK7bu7ZtdtQexAEdHhtZpw3nyD8ywErsm0ScnMDu8MUYIU
         8V2d97iDHAunTNLrXmASqY7dRyvH43rTxKTJcvg1R2MuLdYuFHcWp7AxaDa15MIZ83lU
         BTMuYrxxvfuYm8Vs+5Y5pp/TbhOSAtz9Ifcd8FbUaS4o6N5VReL7GIC+eVtHbWAEYYfw
         Kr+NpFInSRfvNod5qbI0eqR1rZumMsv7wLKlXMfL/Y38Uj+njXW00rrNzhvlfNBJawKn
         SXdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742396401; x=1743001201;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JJbiTGrPF2TdW0St71byyZQG2FKeePQSTcDcIjDX3Pc=;
        b=Uwe0oyAck1p+2MSOR3qwChW/NVrMy1tWpJNyk0/VRmrnLLZO3o6BxevX34PL5VDEn8
         x2fsE2Ci7J7elNEpSzghrs7z6Tz2EHuhb9sOxYce+RTQ5ULF9NvuHU/qKzdCAZ8VShMC
         ewIC8b7KRuoVuw3rmI1AgQVn3vZR/ahNbWCnT7xOUK44aGytepKgQUtu+YVuiD6CYbyy
         ZD4z45hqa02BGoYDUNKL8v+xwOFn5f9yCb3W28HD7b6kdXw7qD3yUsxrZyyJgwnLc2qw
         l7EtPdAdFOhl67gpvpeBwN0F0T0CgfrADMo9vxkgdOMTVmT2E/+IK2tBwOE+P9zKE5Dy
         Ugyg==
X-Forwarded-Encrypted: i=2; AJvYcCWWAxVk5japB/pMAD7xKzbUkbqNxv5zjF8b7uTCJCwxewfcX1bXxvMksu+AJqoMVUmIMVzInQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw+hu2zxKLQ8/yvnaPC85mwbzkaJhetVnbc1YwZvqRQ993652jO
	dzJwbnyG/xPcBv+mZj1ZWyoIlG21nTvWJxHQSYBqz5qOwDkwf0lE
X-Google-Smtp-Source: AGHT+IE4ExOze4s3awjBRHD81GgWD3JJJvLwOSHSJVwkGI844thsOTekl/WFAhHJZssbTb21z18gOQ==
X-Received: by 2002:a92:c249:0:b0:3d2:b66b:94cd with SMTP id e9e14a558f8ab-3d586b14e79mr30970885ab.3.1742396401476;
        Wed, 19 Mar 2025 08:00:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIqzOe2Rr4VFrvhU2PvSq6u1jzCxHklNOlEsU8L4t1aIg==
Received: by 2002:a05:6e02:3cc3:b0:3d1:3d13:5489 with SMTP id
 e9e14a558f8ab-3d584eda1edls10861425ab.0.-pod-prod-02-us; Wed, 19 Mar 2025
 08:00:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXwO9v1su+A/Ve2dMjAhJfveuH5ClLaR/jDnbaEJ2m6cD5w8n6tjv85zbKsjmMpjeyq5G5o0XO3/Lk=@googlegroups.com
X-Received: by 2002:a92:c249:0:b0:3d2:b66b:94cd with SMTP id e9e14a558f8ab-3d586b14e79mr30970455ab.3.1742396400451;
        Wed, 19 Mar 2025 08:00:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742396400; cv=none;
        d=google.com; s=arc-20240605;
        b=k0q0Rm4S101aAmse9wzdjThlaQ25diRjTRjwklW8SHUehGx070o0bOL8hpaMVQ2HM5
         8XGsNKJzesfEfZtRFbx7VLHOUWUgTGcoaVeulib388qob3Sct7ZMv/hv79/BzLmrZxGc
         lro+4/TXOTHqHCR2bHnuCgXcxNFUMKW08tKcCD34oYbALgNu8hF1zlY8LmF50JEvazYt
         tgoz8pJ/YC2iW5RMhJFIV607h7Z7OxPvntieMJNPYhtkJGBFkjehFBaO1wjbbXI3WQJs
         z1IX6Obr2QxONxCcpumgRmANCbdDk7AC4Vf+nJxncnp48LTqCFjrU1kv2FaeKd/n2lMV
         VzpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yc4fWLj+gBuJzwYY9HaGaWX6vmiW43L3kRDUmYvysQ8=;
        fh=hChKoEa1g9VRcojkLGB1vAuEMDSfZYEdCMJyp51sT24=;
        b=LYMJ5LvvvP5bFSfX8OddIQb2aTofuXS8yCUNfQqWq43/BBS5stKjHcTOELb0SgA/DO
         cKwoPnOUQIK2HikJVLlIfGvFEKVj+MAw7P7bJsM+XY5QiyRUC5g0kd0KdqjkYK2MCCYz
         EqZMk6H2/wMEd2hG3fGJJ/WGFAHgO/kTsefg4n9hpVeVGHTk35hSOFQhpA7ocvid8Pty
         ytIQOh/HtjjwFcAiXSd46yiyNgrSv8YNDGEl1fg2mT15RAzN/GJM9fScb3kogKVb3Nwf
         n25BZ0p07qTddPNR6tzKOVqRaUzZ72vA8Tn1rG8q5tj8JN6sQpXQJcGvVXKv31M5wVso
         KucQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TXNJueGA;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f26372bbf4si570701173.1.2025.03.19.08.00.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Mar 2025 08:00:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id d75a77b69052e-4766631a6a4so69873301cf.2
        for <kasan-dev@googlegroups.com>; Wed, 19 Mar 2025 08:00:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWrUTccFNy8GzfFXnmP7O9dKNPcbzkRW1SCxL0xXSzF02iJiOZsw67Lc+G2vAtvIT/oz3rfgxeDFSA=@googlegroups.com
X-Gm-Gg: ASbGnctVUoO35OqbprHIhHS+WaysaWzw7T9sBMiNszh982M+GCjEATHMBAXK/v6475C
	uJdFtglGrtA9K329xUjKRls2dhDUeu0gQe830dCpArRbJma9ISff5Ro2pu/Eu+1+03WB6NREy8t
	9IawuFhr64tlVtVNENSb1cczOFCTo=
X-Received: by 2002:a05:622a:4109:b0:476:6215:eafc with SMTP id
 d75a77b69052e-47708324ad3mr44769101cf.22.1742396399643; Wed, 19 Mar 2025
 07:59:59 -0700 (PDT)
MIME-Version: 1.0
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com> <20250319-sloppy-active-bonobo-f49d8e@leitao>
In-Reply-To: <20250319-sloppy-active-bonobo-f49d8e@leitao>
From: "'Eric Dumazet' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Mar 2025 15:59:48 +0100
X-Gm-Features: AQ5f1Jo0IQiFAXwNIG3GlU8MR-F8G6afdoF9aG6q2eAoals6qX0vz52KIJkaLNY
Message-ID: <CANn89iJAYQsY=-cu=LgsSbfGc6BYVtnAMavD5s8mWM7ipwW7RA@mail.gmail.com>
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
To: Breno Leitao <leitao@debian.org>
Cc: paulmck@kernel.org, kuba@kernel.org, jhs@mojatatu.com, 
	xiyou.wangcong@gmail.com, jiri@resnulli.us, kuniyu@amazon.com, 
	rcu@vger.kernel.org, kasan-dev@googlegroups.com, netdev@vger.kernel.org
Content-Type: multipart/alternative; boundary="00000000000075e5350630b346e5"
X-Original-Sender: edumazet@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TXNJueGA;       spf=pass
 (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::82c
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

--00000000000075e5350630b346e5
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 19, 2025 at 3:56=E2=80=AFPM Breno Leitao <leitao@debian.org> wr=
ote:

> On Wed, Mar 19, 2025 at 03:41:37PM +0100, Eric Dumazet wrote:
> > On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao <leitao@debian.org=
> wrote:
> >
> > > Hello,
> > >
> > > I am experiencing an issue with upstream kernel when compiled with
> debug
> > > capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and
> > > CONFIG_LOCKDEP plus a few others. You can find the full configuration
> at
> > > ....
> > >
> > > Basically when running a `tc replace`, it takes 13-20 seconds to
> finish:
> > >
> > >         # time /usr/sbin/tc qdisc replace dev eth0 root handle 0x1234=
:
> mq
> > >         real    0m13.195s
> > >         user    0m0.001s
> > >         sys     0m2.746s
> > >
> > > While this is running, the machine loses network access completely. T=
he
> > > machine's network becomes inaccessible for 13 seconds above, which is
> far
> > > from
> > > ideal.
> > >
> > > Upon investigation, I found that the host is getting stuck in the
> following
> > > call path:
> > >
> > >         __qdisc_destroy
> > >         mq_attach
> > >         qdisc_graft
> > >         tc_modify_qdisc
> > >         rtnetlink_rcv_msg
> > >         netlink_rcv_skb
> > >         netlink_unicast
> > >         netlink_sendmsg
> > >
> > > The big offender here is rtnetlink_rcv_msg(), which is called with
> > > rtnl_lock
> > > in the follow path:
> > >
> > >         static int tc_modify_qdisc() {
> > >                 ...
> > >                 netdev_lock_ops(dev);
> > >                 err =3D __tc_modify_qdisc(skb, n, extack, dev, tca, t=
cm,
> > > &replay);
> > >                 netdev_unlock_ops(dev);
> > >                 ...
> > >         }
> > >
> > > So, the rtnl_lock is held for 13 seconds in the case above. I also
> > > traced that __qdisc_destroy() is called once per NIC queue, totalling
> > > a total of 250 calls for the cards I am using.
> > >
> > > Ftrace output:
> > >
> > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle
> 0x1: mq
> > > | grep \\$
> > >         7) $ 4335849 us  |        } /* mq_init */
> > >         7) $ 4339715 us  |      } /* qdisc_create */
> > >         11) $ 15844438 us |        } /* mq_attach */
> > >         11) $ 16129620 us |      } /* qdisc_graft */
> > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> > >
> > >         In this case, the rtnetlink_rcv_msg() took 20 seconds, and,
> while
> > > it
> > >         was running, the NIC was not being able to send any packet
> > >
> > > Going one step further, this matches what I described above:
> > >
> > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle
> 0x1: mq
> > > | grep "\\@\|\\$"
> > >
> > >         7) $ 4335849 us  |        } /* mq_init */
> > >         7) $ 4339715 us  |      } /* qdisc_create */
> > >         14) @ 210619.0 us |                      } /* schedule */
> > >         14) @ 210621.3 us |                    } /* schedule_timeout =
*/
> > >         14) @ 210654.0 us |                  } /*
> > > wait_for_completion_state */
> > >         14) @ 210716.7 us |                } /* __wait_rcu_gp */
> > >         14) @ 210719.4 us |              } /* synchronize_rcu_normal =
*/
> > >         14) @ 210742.5 us |            } /* synchronize_rcu */
> > >         14) @ 144455.7 us |            } /* __qdisc_destroy */
> > >         14) @ 144458.6 us |          } /* qdisc_put */
> > >         <snip>
> > >         2) @ 131083.6 us |                        } /* schedule */
> > >         2) @ 131086.5 us |                      } /* schedule_timeout
> */
> > >         2) @ 131129.6 us |                    } /*
> > > wait_for_completion_state */
> > >         2) @ 131227.6 us |                  } /* __wait_rcu_gp */
> > >         2) @ 131231.0 us |                } /* synchronize_rcu_normal
> */
> > >         2) @ 131242.6 us |              } /* synchronize_rcu */
> > >         2) @ 152162.7 us |            } /* __qdisc_destroy */
> > >         2) @ 152165.7 us |          } /* qdisc_put */
> > >         11) $ 15844438 us |        } /* mq_attach */
> > >         11) $ 16129620 us |      } /* qdisc_graft */
> > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> > >
> > > From the stack trace, it appears that most of the time is spent waiti=
ng
> > > for the
> > > RCU grace period to free the qdisc (!?):
> > >
> > >         static void __qdisc_destroy(struct Qdisc *qdisc)
> > >         {
> > >                 if (ops->destroy)
> > >                         ops->destroy(qdisc);
> > >
> > >                 call_rcu(&qdisc->rcu, qdisc_free_cb);
> > >
> >
> > call_rcu() is asynchronous, this is very different from
> synchronize_rcu().
>
> That is a good point. The offender is synchronize_rcu() is here.
> >
> >
> > >         }
> > >
> > > So, from my newbie PoV, the issue can be summarized as follows:
> > >
> > >         netdev_lock_ops(dev);
> > >         __tc_modify_qdisc()
> > >           qdisc_graft()
> > >             for (i =3D 0; i <  255; i++)
> > >               qdisc_put()
> > >                 ____qdisc_destroy()
> > >                   call_rcu()
> > >               }
> > >
> > > Questions:
> > >
> > > 1) I assume the egress traffic is blocked because we are modifying th=
e
> > >    qdisc, which makes sense. How is this achieved? Is it related to
> > >    rtnl_lock?
> > >
> > > 2) Would it be beneficial to attempt qdisc_put() outside of the
> critical
> > >    section (rtnl_lock?) to prevent this freeze?
> > >
> > >
> >
> > It is unclear to me why you have syncrhonize_rcu() calls.
>
> This is coming from:
>
>         __qdisc_destroy() {
>                 lockdep_unregister_key(&qdisc->root_lock_key) {
>                         ...
>                         /* Wait until is_dynamic_key() has finished
> accessing k->hash_entry. */
>                         synchronize_rcu();
>


Sure, this is an additional cost because of lockdep.

Perhaps something can be done there, if anyone cares.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANn89iJAYQsY%3D-cu%3DLgsSbfGc6BYVtnAMavD5s8mWM7ipwW7RA%40mail.gmail.com.

--00000000000075e5350630b346e5
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote g=
mail_quote_container"><div dir=3D"ltr" class=3D"gmail_attr">On Wed, Mar 19,=
 2025 at 3:56=E2=80=AFPM Breno Leitao &lt;<a href=3D"mailto:leitao@debian.o=
rg">leitao@debian.org</a>&gt; wrote:<br></div><blockquote class=3D"gmail_qu=
ote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,20=
4);padding-left:1ex">On Wed, Mar 19, 2025 at 03:41:37PM +0100, Eric Dumazet=
 wrote:<br>
&gt; On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao &lt;<a href=3D"ma=
ilto:leitao@debian.org" target=3D"_blank">leitao@debian.org</a>&gt; wrote:<=
br>
&gt; <br>
&gt; &gt; Hello,<br>
&gt; &gt;<br>
&gt; &gt; I am experiencing an issue with upstream kernel when compiled wit=
h debug<br>
&gt; &gt; capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and<br>
&gt; &gt; CONFIG_LOCKDEP plus a few others. You can find the full configura=
tion at<br>
&gt; &gt; ....<br>
&gt; &gt;<br>
&gt; &gt; Basically when running a `tc replace`, it takes 13-20 seconds to =
finish:<br>
&gt; &gt;<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0# time /usr/sbin/tc qdisc replac=
e dev eth0 root handle 0x1234: mq<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0real=C2=A0 =C2=A0 0m13.195s<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0user=C2=A0 =C2=A0 0m0.001s<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0sys=C2=A0 =C2=A0 =C2=A00m2.746s<=
br>
&gt; &gt;<br>
&gt; &gt; While this is running, the machine loses network access completel=
y. The<br>
&gt; &gt; machine&#39;s network becomes inaccessible for 13 seconds above, =
which is far<br>
&gt; &gt; from<br>
&gt; &gt; ideal.<br>
&gt; &gt;<br>
&gt; &gt; Upon investigation, I found that the host is getting stuck in the=
 following<br>
&gt; &gt; call path:<br>
&gt; &gt;<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0__qdisc_destroy<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0mq_attach<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0qdisc_graft<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0tc_modify_qdisc<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0rtnetlink_rcv_msg<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netlink_rcv_skb<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netlink_unicast<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netlink_sendmsg<br>
&gt; &gt;<br>
&gt; &gt; The big offender here is rtnetlink_rcv_msg(), which is called wit=
h<br>
&gt; &gt; rtnl_lock<br>
&gt; &gt; in the follow path:<br>
&gt; &gt;<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0static int tc_modify_qdisc() {<b=
r>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0...<=
br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netd=
ev_lock_ops(dev);<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0err =
=3D __tc_modify_qdisc(skb, n, extack, dev, tca, tcm,<br>
&gt; &gt; &amp;replay);<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netd=
ev_unlock_ops(dev);<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0...<=
br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0}<br>
&gt; &gt;<br>
&gt; &gt; So, the rtnl_lock is held for 13 seconds in the case above. I als=
o<br>
&gt; &gt; traced that __qdisc_destroy() is called once per NIC queue, total=
ling<br>
&gt; &gt; a total of 250 calls for the cards I am using.<br>
&gt; &gt;<br>
&gt; &gt; Ftrace output:<br>
&gt; &gt;<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0# perf ftrace --graph-opts depth=
=3D100,tail,noirqs -G<br>
&gt; &gt; rtnetlink_rcv_msg=C2=A0 =C2=A0/usr/sbin/tc qdisc replace dev eth0=
 root handle 0x1: mq<br>
&gt; &gt; | grep \\$<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A07) $ 4335849 us=C2=A0 |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 } /* mq_init */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A07) $ 4339715 us=C2=A0 |=C2=A0 =
=C2=A0 =C2=A0 } /* qdisc_create */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 15844438 us |=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 } /* mq_attach */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 16129620 us |=C2=A0 =C2=A0=
 =C2=A0 } /* qdisc_graft */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 20469368 us |=C2=A0 =C2=A0=
 } /* tc_modify_qdisc */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 20470448 us |=C2=A0 } /* r=
tnetlink_rcv_msg */<br>
&gt; &gt;<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0In this case, the rtnetlink_rcv_=
msg() took 20 seconds, and, while<br>
&gt; &gt; it<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0was running, the NIC was not bei=
ng able to send any packet<br>
&gt; &gt;<br>
&gt; &gt; Going one step further, this matches what I described above:<br>
&gt; &gt;<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0# perf ftrace --graph-opts depth=
=3D100,tail,noirqs -G<br>
&gt; &gt; rtnetlink_rcv_msg=C2=A0 =C2=A0/usr/sbin/tc qdisc replace dev eth0=
 root handle 0x1: mq<br>
&gt; &gt; | grep &quot;\\@\|\\$&quot;<br>
&gt; &gt;<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A07) $ 4335849 us=C2=A0 |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 } /* mq_init */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A07) $ 4339715 us=C2=A0 |=C2=A0 =
=C2=A0 =C2=A0 } /* qdisc_create */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210619.0 us |=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* schedu=
le */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210621.3 us |=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* schedule_time=
out */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210654.0 us |=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /*<br>
&gt; &gt; wait_for_completion_state */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210716.7 us |=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __wait_rcu_gp */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210719.4 us |=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu_normal */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210742.5 us |=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 144455.7 us |=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __qdisc_destroy */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 144458.6 us |=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 } /* qdisc_put */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0&lt;snip&gt;<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131083.6 us |=C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* =
schedule */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131086.5 us |=C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* schedul=
e_timeout */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131129.6 us |=C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /*<br>
&gt; &gt; wait_for_completion_state */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131227.6 us |=C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __wait_rcu_gp */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131231.0 us |=C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu_normal */<br=
>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131242.6 us |=C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 152162.7 us |=C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __qdisc_destroy */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 152165.7 us |=C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 } /* qdisc_put */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 15844438 us |=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 } /* mq_attach */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 16129620 us |=C2=A0 =C2=A0=
 =C2=A0 } /* qdisc_graft */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 20469368 us |=C2=A0 =C2=A0=
 } /* tc_modify_qdisc */<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 20470448 us |=C2=A0 } /* r=
tnetlink_rcv_msg */<br>
&gt; &gt;<br>
&gt; &gt; From the stack trace, it appears that most of the time is spent w=
aiting<br>
&gt; &gt; for the<br>
&gt; &gt; RCU grace period to free the qdisc (!?):<br>
&gt; &gt;<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0static void __qdisc_destroy(stru=
ct Qdisc *qdisc)<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0{<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (=
ops-&gt;destroy)<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0ops-&gt;destroy(qdisc);<br>
&gt; &gt;<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0call=
_rcu(&amp;qdisc-&gt;rcu, qdisc_free_cb);<br>
&gt; &gt;<br>
&gt; <br>
&gt; call_rcu() is asynchronous, this is very different from synchronize_rc=
u().<br>
<br>
That is a good point. The offender is synchronize_rcu() is here.<br>
&gt; <br>
&gt; <br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0}<br>
&gt; &gt;<br>
&gt; &gt; So, from my newbie PoV, the issue can be summarized as follows:<b=
r>
&gt; &gt;<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netdev_lock_ops(dev);<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0__tc_modify_qdisc()<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0qdisc_graft()<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0for (i =3D 0; i &l=
t;=C2=A0 255; i++)<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0qdisc_put()=
<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0____=
qdisc_destroy()<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0call_rcu()<br>
&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0}<br>
&gt; &gt;<br>
&gt; &gt; Questions:<br>
&gt; &gt;<br>
&gt; &gt; 1) I assume the egress traffic is blocked because we are modifyin=
g the<br>
&gt; &gt;=C2=A0 =C2=A0 qdisc, which makes sense. How is this achieved? Is i=
t related to<br>
&gt; &gt;=C2=A0 =C2=A0 rtnl_lock?<br>
&gt; &gt;<br>
&gt; &gt; 2) Would it be beneficial to attempt qdisc_put() outside of the c=
ritical<br>
&gt; &gt;=C2=A0 =C2=A0 section (rtnl_lock?) to prevent this freeze?<br>
&gt; &gt;<br>
&gt; &gt;<br>
&gt; <br>
&gt; It is unclear to me why you have syncrhonize_rcu() calls.<br>
<br>
This is coming from:<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 __qdisc_destroy() {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 lockdep_unregister_=
key(&amp;qdisc-&gt;root_lock_key) {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 ...<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 /* Wait until is_dynamic_key() has finished accessing k-&gt;hash=
_entry. */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 synchronize_rcu();<br></blockquote><div><br></div><div><br></div=
><div>Sure, this is an additional cost because of lockdep.</div><div><br></=
div><div>Perhaps something can be done there, if anyone cares.</div><div><b=
r></div><div><br></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CANn89iJAYQsY%3D-cu%3DLgsSbfGc6BYVtnAMavD5s8mWM7ipwW7RA%40mail.gm=
ail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/CANn89iJAYQsY%3D-cu%3DLgsSbfGc6BYVtnAMavD5s8mWM7ipwW7RA%40=
mail.gmail.com</a>.<br />

--00000000000075e5350630b346e5--
