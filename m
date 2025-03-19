Return-Path: <kasan-dev+bncBCS4VDMYRUNBBN6W5O7AMGQE2QQRIZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id EAEFFA69449
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 17:05:13 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-3010db05acfsf7779390a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 09:05:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742400312; cv=pass;
        d=google.com; s=arc-20240605;
        b=SKRSk5c0zQ56MQGfVX66iVIr31YCK5c/6uCY5TJRUYwYFr+6OBComgfizwOJFcU/Io
         +kN04SDo0tpJZ4bYq1azvY+H+7FOzW6d87NUkR1cf6vJLeb0/yUNG3ileN0tMsxCYBTA
         rws4fCQ9ZbFgfOm/x73ukDw7HEDW/R4QZkSKMXGwaoJ8spua+UTsRDTcHGz7pZqVeFMh
         WP4DVcu8Kn7iY3SY4PuYaGrxNoR9pjnEUU784AYMD2QUKb/E39YIBpaIRqInZCmXasyR
         ci5albyrbi6BumFDAh2eoCeyGcgsI1gSv0Wgpn9OPnc1QSDVcqwviLR2VT/W+ZF3Ttq0
         u1KA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=HMUHACGUHAzjZWq4u0sQG/r+zKH5Hk+uZ/3j0Y+W3II=;
        fh=/+DMtj7Dzf6yfAqIVAx1/6yxY7N43LgXpNr4jkzYW5w=;
        b=jmKSXPmCJxaT8SmSPwq/tuBBUxHxAQx+Vxpo3FKwixrwRx8rGbHAPJ9dx3xVjo5OIO
         6/4pw42pdcxra76QMrZqQ3p3PxtLeiS9dDzI+ax2A1nzPrb99I5kQFM26yXCe/f2HKvT
         fmWl38akbv5V4iigr8I/xz9+mXJAJAu+xvXvMfcGb7rHwt7YiWXBc0yDmmaB5pIw99Ok
         pc504lZKmC9Ae4K1+MquKW24a1BsYUVIDu+F6BIDKmnPdYy1K4g9PO/7WAffJT+lnqSS
         l9ODHHwjOI36kdTwvXXlBVP9LfueK7kHPjk+ijH171xHGxtw67eR0twD8kVHbIwZqFf/
         Z14g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LQx3B8rQ;
       spf=pass (google.com: domain of srs0=en1s=wg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=eN1s=WG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742400312; x=1743005112; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=HMUHACGUHAzjZWq4u0sQG/r+zKH5Hk+uZ/3j0Y+W3II=;
        b=htvPBU/ZSndPFn77hD0Gb++WIQnpSu89zOBISgNCWf28B1ts3HN69Iez6j3+lV21aj
         dNCPKAQmR7JJw35VmrlKreDf97oDAiPf/uNKbPCYtywOlm9SWJzdw9ULRxEyMOTQT1F9
         I011ZHEhyxTiO+W9zxkr/pa4KknNPzgdBc3/nuFy0yDt4fmW2M5DH25SVrlJot6F7aNO
         YlfWFgVUTFl+Ph9uTYJkDzI1EoqZtwtDV/qRZrZG5z7M92A70pn33WCuHOKE4AS12EA4
         qQ2DSRVhCrnfuuZ6TTTB85juHphSuekYHF2oHpawPDIN6Th0EZpPL1tpVOoWgVClqa/a
         PFXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742400312; x=1743005112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=HMUHACGUHAzjZWq4u0sQG/r+zKH5Hk+uZ/3j0Y+W3II=;
        b=oO7dbhLP1EOcJ1mJ6CUUUlOTO+WvJOsDQO1O1U2+LScostPn8ke9Yruhgw9san1rHp
         0VCD3LXEn69tEAyRX/kvd+A2hFxDNEAT1y1zMt9r1rYz0T+dh204xlsOngtizSGRn5rQ
         5A9yM/9umNJAE9T+90fccPxmvDKz4uO9XKNinTX01mDyAA/RWhcFYYIUwVu91npwGBcI
         JTFBL7mxROEGS1g8LKeBV1/VE1J3aFHRNEPjM4Dd7IFW7KlvK6iJjp7r11ZQIyp+Ictt
         +zm5C0BdqMU1506XYpfg+uW42D118AN5xe/1Uv1u5DCu37Pnz4978uHl8BeKFvnq+xjg
         sqwA==
X-Forwarded-Encrypted: i=2; AJvYcCX19hMurMrqawnUgEwEMcQYzEnt/1es3kGKevMeToZZUY/LMF5FlWUHzFX1R8PwpfLDi3AOKw==@lfdr.de
X-Gm-Message-State: AOJu0YyGiM1l1kamlzFN/LiMdsuJI3pxzQrtmOWsyMZAy+Bs1fvG5mAg
	81BJ74PeXws6Q4V0cLHotcY6WEevJg0VPHhVk9cipj/5A/ldl4bP
X-Google-Smtp-Source: AGHT+IFCsjgatSVdpgqahjvnCix75S/UNdoO/zjJ75eMIRHAuU2GNaqTmMqcyyBwjS82EENCSZQy/Q==
X-Received: by 2002:a17:90b:3b51:b0:2fe:afbc:cd53 with SMTP id 98e67ed59e1d1-301be201f80mr4699605a91.28.1742400311874;
        Wed, 19 Mar 2025 09:05:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKzHeY+TQNP025ebrLy03Cn4w3Vf4ICUQ6NMleC0IcWJg==
Received: by 2002:a17:90a:6d61:b0:301:c125:45b0 with SMTP id
 98e67ed59e1d1-301d41e8da3ls11509a91.2.-pod-prod-04-us; Wed, 19 Mar 2025
 09:05:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDQNkKcD3AzoniPJ1kJqvSY/03aD+Miw2pTdZrnkGNOXm24/OZHSLQLzSzA2O9P2BEyJRhJ6yajpo=@googlegroups.com
X-Received: by 2002:a17:90b:3e50:b0:2f4:434d:c7f0 with SMTP id 98e67ed59e1d1-301bde6d7cemr6731830a91.12.1742400309481;
        Wed, 19 Mar 2025 09:05:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742400309; cv=none;
        d=google.com; s=arc-20240605;
        b=azZTT2NjWxRtBeSSm+HG5U1I6NTHQ9NoqbG8CXtRdexJVfcaoHNB8wrULDJ4e9Sqj2
         bh2hNhIwxANUvSQBaBovpYcCU7AHuFs1xczQ8CWD++gZowZlEMINobT8TtEhAVzK8Fr+
         on0Sv58A5gLxL+C0xfj9DGZ+VHUSTKLiVppkSK0u9xTQLYBpfCubFhtzqznhMbtPocMo
         Z9ZQuAighsUJHihnlgvl2CekKoqjW+J6n+gVSJh13PvbSljM4ivwEUVsc2VTehWBZ/QP
         zsh0R1sA/JOIqeZlrrRf0yFyhY+WFFEd5Y0T9gomxJ1PJJ0Ct3SZkUmT683EAyvKfAOx
         t0ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=TSQ08Du7xca7o820hg8r38B3FMJiA+rgTlf536nknBw=;
        fh=85ZNJ/59MuwVj9iMP9CLYE6PD5EjCFeBfPU5klvpZOs=;
        b=ADiLVKVfuQvqk8Ius7eWjwIOJHObEZTKl948rQCj8egJsp9K+IdoCPaTahS6A3ejDm
         PA6Ssrd5uQNChEgI+198kKSQBQ8TUoKUScBWgxCNFBR4FNaRv7Fq3YvA8thna53tuGkh
         eQfBC83yYJ2hdpZH8oq1Ne26243TMR2W0knZ1zKqE54G8/G7cRGGsAuQsZE8iu7erjHc
         NraA2vTrZ9IomtqsCc4Rwcmb9uAHVn69tjBJhPBI0zsJJ3EfGzELh2I8lxycG7E0HSI1
         GXJdCBD3RZlTMEsl5f+Up1+6Ljdo0YM3owKvSQmfsyYyPmvCOTRle7O7gBWQmYJlqFxu
         vGQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LQx3B8rQ;
       spf=pass (google.com: domain of srs0=en1s=wg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=eN1s=WG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-301bf476c11si77923a91.1.2025.03.19.09.05.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Mar 2025 09:05:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=en1s=wg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 156D0A491F5;
	Wed, 19 Mar 2025 15:59:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3AB1FC4CEE4;
	Wed, 19 Mar 2025 16:05:08 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id E2C3FCE0BC5; Wed, 19 Mar 2025 09:05:07 -0700 (PDT)
Date: Wed, 19 Mar 2025 09:05:07 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Eric Dumazet <edumazet@google.com>
Cc: Breno Leitao <leitao@debian.org>, kuba@kernel.org, jhs@mojatatu.com,
	xiyou.wangcong@gmail.com, jiri@resnulli.us, kuniyu@amazon.com,
	rcu@vger.kernel.org, kasan-dev@googlegroups.com,
	netdev@vger.kernel.org
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
Message-ID: <0e9dbde7-07eb-45f1-a39c-6cf76f9c252f@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
 <20250319-sloppy-active-bonobo-f49d8e@leitao>
 <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
 <CANn89iKdJfkPrY1rHjzUn5nPbU5Z+VAuW5Le2PraeVuHVQ264g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANn89iKdJfkPrY1rHjzUn5nPbU5Z+VAuW5Le2PraeVuHVQ264g@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LQx3B8rQ;       spf=pass
 (google.com: domain of srs0=en1s=wg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=eN1s=WG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Wed, Mar 19, 2025 at 04:08:48PM +0100, Eric Dumazet wrote:
> On Wed, Mar 19, 2025 at 4:04=E2=80=AFPM Paul E. McKenney <paulmck@kernel.=
org> wrote:
>=20
> > On Wed, Mar 19, 2025 at 07:56:40AM -0700, Breno Leitao wrote:
> > > On Wed, Mar 19, 2025 at 03:41:37PM +0100, Eric Dumazet wrote:
> > > > On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao <leitao@debian=
.org>
> > wrote:
> > > >
> > > > > Hello,
> > > > >
> > > > > I am experiencing an issue with upstream kernel when compiled wit=
h
> > debug
> > > > > capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and
> > > > > CONFIG_LOCKDEP plus a few others. You can find the full
> > configuration at
> > > > > ....
> > > > >
> > > > > Basically when running a `tc replace`, it takes 13-20 seconds to
> > finish:
> > > > >
> > > > >         # time /usr/sbin/tc qdisc replace dev eth0 root handle
> > 0x1234: mq
> > > > >         real    0m13.195s
> > > > >         user    0m0.001s
> > > > >         sys     0m2.746s
> > > > >
> > > > > While this is running, the machine loses network access completel=
y.
> > The
> > > > > machine's network becomes inaccessible for 13 seconds above, whic=
h
> > is far
> > > > > from
> > > > > ideal.
> > > > >
> > > > > Upon investigation, I found that the host is getting stuck in the
> > following
> > > > > call path:
> > > > >
> > > > >         __qdisc_destroy
> > > > >         mq_attach
> > > > >         qdisc_graft
> > > > >         tc_modify_qdisc
> > > > >         rtnetlink_rcv_msg
> > > > >         netlink_rcv_skb
> > > > >         netlink_unicast
> > > > >         netlink_sendmsg
> > > > >
> > > > > The big offender here is rtnetlink_rcv_msg(), which is called wit=
h
> > > > > rtnl_lock
> > > > > in the follow path:
> > > > >
> > > > >         static int tc_modify_qdisc() {
> > > > >                 ...
> > > > >                 netdev_lock_ops(dev);
> > > > >                 err =3D __tc_modify_qdisc(skb, n, extack, dev, tc=
a,
> > tcm,
> > > > > &replay);
> > > > >                 netdev_unlock_ops(dev);
> > > > >                 ...
> > > > >         }
> > > > >
> > > > > So, the rtnl_lock is held for 13 seconds in the case above. I als=
o
> > > > > traced that __qdisc_destroy() is called once per NIC queue, total=
ling
> > > > > a total of 250 calls for the cards I am using.
> > > > >
> > > > > Ftrace output:
> > > > >
> > > > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> > > > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root hand=
le
> > 0x1: mq
> > > > > | grep \\$
> > > > >         7) $ 4335849 us  |        } /* mq_init */
> > > > >         7) $ 4339715 us  |      } /* qdisc_create */
> > > > >         11) $ 15844438 us |        } /* mq_attach */
> > > > >         11) $ 16129620 us |      } /* qdisc_graft */
> > > > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> > > > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> > > > >
> > > > >         In this case, the rtnetlink_rcv_msg() took 20 seconds, an=
d,
> > while
> > > > > it
> > > > >         was running, the NIC was not being able to send any packe=
t
> > > > >
> > > > > Going one step further, this matches what I described above:
> > > > >
> > > > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> > > > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root hand=
le
> > 0x1: mq
> > > > > | grep "\\@\|\\$"
> > > > >
> > > > >         7) $ 4335849 us  |        } /* mq_init */
> > > > >         7) $ 4339715 us  |      } /* qdisc_create */
> > > > >         14) @ 210619.0 us |                      } /* schedule */
> > > > >         14) @ 210621.3 us |                    } /* schedule_time=
out
> > */
> > > > >         14) @ 210654.0 us |                  } /*
> > > > > wait_for_completion_state */
> > > > >         14) @ 210716.7 us |                } /* __wait_rcu_gp */
> > > > >         14) @ 210719.4 us |              } /* synchronize_rcu_nor=
mal
> > */
> > > > >         14) @ 210742.5 us |            } /* synchronize_rcu */
> > > > >         14) @ 144455.7 us |            } /* __qdisc_destroy */
> > > > >         14) @ 144458.6 us |          } /* qdisc_put */
> > > > >         <snip>
> > > > >         2) @ 131083.6 us |                        } /* schedule *=
/
> > > > >         2) @ 131086.5 us |                      } /*
> > schedule_timeout */
> > > > >         2) @ 131129.6 us |                    } /*
> > > > > wait_for_completion_state */
> > > > >         2) @ 131227.6 us |                  } /* __wait_rcu_gp */
> > > > >         2) @ 131231.0 us |                } /*
> > synchronize_rcu_normal */
> > > > >         2) @ 131242.6 us |              } /* synchronize_rcu */
> > > > >         2) @ 152162.7 us |            } /* __qdisc_destroy */
> > > > >         2) @ 152165.7 us |          } /* qdisc_put */
> > > > >         11) $ 15844438 us |        } /* mq_attach */
> > > > >         11) $ 16129620 us |      } /* qdisc_graft */
> > > > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> > > > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> > > > >
> > > > > From the stack trace, it appears that most of the time is spent
> > waiting
> > > > > for the
> > > > > RCU grace period to free the qdisc (!?):
> > > > >
> > > > >         static void __qdisc_destroy(struct Qdisc *qdisc)
> > > > >         {
> > > > >                 if (ops->destroy)
> > > > >                         ops->destroy(qdisc);
> > > > >
> > > > >                 call_rcu(&qdisc->rcu, qdisc_free_cb);
> > > > >
> > > >
> > > > call_rcu() is asynchronous, this is very different from
> > synchronize_rcu().
> > >
> > > That is a good point. The offender is synchronize_rcu() is here.
> >
> > Should that be synchronize_net()?
> >
>=20
> I think we should redesign lockdep_unregister_key() to work on a separate=
ly
> allocated piece of memory,
> then use kfree_rcu() in it.
>=20
> Ie not embed a "struct lock_class_key" in the struct Qdisc, but a pointer=
 to
>=20
> struct ... {
>      struct lock_class_key;
>      struct rcu_head  rcu;
> }

Works for me!

                                                        Thanx, Paul

> > > > >         }
> > > > >
> > > > > So, from my newbie PoV, the issue can be summarized as follows:
> > > > >
> > > > >         netdev_lock_ops(dev);
> > > > >         __tc_modify_qdisc()
> > > > >           qdisc_graft()
> > > > >             for (i =3D 0; i <  255; i++)
> > > > >               qdisc_put()
> > > > >                 ____qdisc_destroy()
> > > > >                   call_rcu()
> > > > >               }
> > > > >
> > > > > Questions:
> > > > >
> > > > > 1) I assume the egress traffic is blocked because we are modifyin=
g
> > the
> > > > >    qdisc, which makes sense. How is this achieved? Is it related =
to
> > > > >    rtnl_lock?
> > > > >
> > > > > 2) Would it be beneficial to attempt qdisc_put() outside of the
> > critical
> > > > >    section (rtnl_lock?) to prevent this freeze?
> > > > >
> > > > >
> > > >
> > > > It is unclear to me why you have syncrhonize_rcu() calls.
> > >
> > > This is coming from:
> > >
> > >       __qdisc_destroy() {
> > >               lockdep_unregister_key(&qdisc->root_lock_key) {
> > >                       ...
> > >                       /* Wait until is_dynamic_key() has finished
> > accessing k->hash_entry. */
> > >                       synchronize_rcu();
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
e9dbde7-07eb-45f1-a39c-6cf76f9c252f%40paulmck-laptop.
