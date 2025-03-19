Return-Path: <kasan-dev+bncBDN3ZEGJT4NBBDN45O7AMGQEXXHZ6SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CF04A69264
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 16:09:03 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-7271d7436acsf7146635a34.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 08:09:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742396941; cv=pass;
        d=google.com; s=arc-20240605;
        b=X1WFmu0YWLjnGFHV1ppCK8aaCe9cxiPNVv4QM8r16apquzxYmWzw2PMJErmQvJC7AY
         AENTxpXlK9NdPTOsE0pIKuEUPH6TiCGDQNAxeENOJYJs9Nbw/cWOSd6lPFNsY/2SHuCP
         uSuuE3+quFZqYVEc6D5rYt8RmhP0QsLZ7FwrFfesOdwbLzGNgwcVyJ5qBzzDicjIWxpv
         MbeWfZmdCIhhYkawzoo5Fj+XYJ5D/WbS8KyM+AjUvpuOgJL45i7S7m3mrhyzyRm09OiD
         FLD/EBFeVayYFDgZ1nHCWGVy6v+sRRcDXqRspHhOukSUrtus5BCuAU50jewdZgxxkpPP
         fl5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=N2YbKq5TXxN+6Ht6ep6CGKLbQsg1ZQTyKYySAXn7CxQ=;
        fh=iCaPBl/vj304p1kBGos71FiLV1mQtCnsJ/hXnAJMBgA=;
        b=bOGc4rJC3UeyIxOB6L5rkpX3iKh3sdFiV2qrQqaoEtUMVIgdPvY93XeFrJJgokmCAg
         Ig8oXSmVt9Wbf4Q0cRa+FjGzWil28eTVVFDKEcGrTuholi4MGITVlBA+1ru40tsD1JLj
         aJNqIWuIE/OWMBwxYqQtjgIEp6rQFSDVuzb1V7x8LIFltQHQWTMhRS5oH3Z/g1bSZu5y
         imR6A0LWnKUvdigjWF4xTRICwHWZ8SbGgXrqHQ6pFs5TxwBT28Nw8nvW5IDsHuHpCdCo
         E4z5BT15ht33srlttOjv8o5l5vbz4R54F0sEoV+EFuwxEpgRsuGXCzfg0h0pD5gnmGu6
         pglw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=scgNnQPU;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742396941; x=1743001741; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=N2YbKq5TXxN+6Ht6ep6CGKLbQsg1ZQTyKYySAXn7CxQ=;
        b=P/jGVdjLI0F9QDtKnN4hflpXcHPBdKX6C3HtodBuXUxYPgKHem5XA7NesmFcJNOi+U
         afMOjHkLuTphRIQze9OVGs78i4Z0pnpdlj0PRWia9pK1OcTSdUX0Cz7p+iBNZ0YILPav
         465iRqvJCPYfkWZSgw75tIc1J9VRo1dl6SY+FPdfN7v8X3BVJBzSrqLUhmNBR7D7LnBA
         RUVKgALWkOMEfdHpvfvsfG4oUOzLnill9KUELeLoHpdE/O5k7rtii+kcAxvjTwO5RFv9
         5c7F/XZNNx1RkrWkcrjWNqvSWK1IXEqRJfnBuRJWsVzK+AokcAMEXJZOGuc8/fImShiq
         DFhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742396941; x=1743001741;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N2YbKq5TXxN+6Ht6ep6CGKLbQsg1ZQTyKYySAXn7CxQ=;
        b=YLGEfe49tDl1AtstrPcRihrWst7RA0zzuUYcU6wGSCnI94dcNnqdaEg2dkjLdjuNWp
         /RL4PINb72gA7bK74WeGgh4U8cPAZ0YBQBWzX1ICkuj5cp8/Jx8f4LVHZNUMM40OGWXn
         YJmz0JW5EpOEi5LVZFL9N+TrbicX4+AG7duqKhFfUWG95pAYcxPJTmBDA3HSyBKjUwnX
         Hal1ZFAiTcRStb6rpxQXADqHoD9wdfBi5KwgGPCZP33cEedxgFGAj5ntcJyXMAJ0X35L
         cSZLN+B8oRnO/A8mend/pSa/9JhflxHginFSzvlstc5RZmHNmTsv3UoBURycf71HTNON
         igfg==
X-Forwarded-Encrypted: i=2; AJvYcCWHsQYnjSSaCUYIsZ2gaX4C7osKyk4iaKkl52MeduaBXgQ+5WIw5wxUmR/43zUxYoc0f+PY/g==@lfdr.de
X-Gm-Message-State: AOJu0YxT2cx/dLEE/XJo8xcIoJdPf9739UoF9U+GdAJeNlJqxv42g8NN
	T/8OclGvDHp/GlEfV1kG0WkgnKf1GwzmBgbkHS1khVN8APi+T7JT
X-Google-Smtp-Source: AGHT+IGi3zs5WypuysSPmXuQRi+aOrh3TusnJqnF3GhOQoahe+Q4q2V8c9JibVh2QXfWm4GsFMP2JQ==
X-Received: by 2002:a05:6830:6e89:b0:72b:9387:84be with SMTP id 46e09a7af769-72bfbdbd203mr2547068a34.1.1742396941237;
        Wed, 19 Mar 2025 08:09:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJ6g/1mt62yQUjRqnvAjWNnucc45l2M8bs+e3qBH2JAcg==
Received: by 2002:a05:6870:3314:b0:29f:aff3:65c8 with SMTP id
 586e51a60fabf-2c667a56711ls1236530fac.2.-pod-prod-08-us; Wed, 19 Mar 2025
 08:09:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXEyRVtYAZ0wkuNNE8oWGkWtuNh1th49c5/AGh3MMejIOys0ie8I3ZWN16L4j3GZYnD4FuFLcBEN7Q=@googlegroups.com
X-Received: by 2002:a05:6870:b24f:b0:2c1:5dbb:ecb6 with SMTP id 586e51a60fabf-2c745a2de60mr2290120fac.38.1742396940222;
        Wed, 19 Mar 2025 08:09:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742396940; cv=none;
        d=google.com; s=arc-20240605;
        b=APOIS26okV5ue9/+4TaUSJUi4WXDv+sOZn9szSteOcPMSRydyiBwZxX4teI5kk+B8U
         otq+Y4m4nMAPyWsKpzdatCawTcbbvXfgzXeepM91D5x0O7kErtCDGSkyl9Q+Mqgkr0dh
         P7Gcz2uqX4lOrxa4qqMuOeK2PnZ+c7ZxnD4ovpk/fmJ688MZ/x7eihSNsfAmyhymvmSc
         7RxsemLyBXw8p+kUSSbBT0+Fw2VDwQZ1u19X2J561PU39zxHsJtlPmFor/17tvlFfsEC
         2p7m+ZNfwbfRoFIsNyo8X6Y2YHAYzxb1x0bhdM3brKSvI+CXF8DdQaABjQX3rZvgHPBu
         hTYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sPs0Y462auDlWd753vypyvtxL5NcqgHQuwpo7hW4ZUI=;
        fh=JyDLlruhgFie/dq14MTRKcKicvvzjmPrpqN32DcVbZk=;
        b=EqgEtgz9VCwIOa1lgzoY1wqeWcuQ1mR/ZnBo+eV7PHGxkZGUIqVAj7AxwzrYC2ps3V
         ZGgNwB4HbahBPrFdJ8M0uWf15AM04oHvlPj6yq7eAia0wrF5cB6yPHXa0mo07DLFenwy
         Lfcc+WWOkWbdthJceBanlONhac/W8dL4p5KLWHqSVqA7pf07Ttf0jSW8GqO1zsSZeCB9
         lmOoxidEfZy0vJJ61bBF6aQbrqVyyKPuHEV3gurKa1qaHDtm/vCEHZ7c4rycsIdIaqiJ
         aN+rMzN4DgLL7eHtb37GhE/bRdwGOZrC3Dzsvx40DoARqaE1uMgoztBDXA4naVfUEHY/
         Iq2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=scgNnQPU;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2c67127c2b3si671768fac.4.2025.03.19.08.09.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Mar 2025 08:09:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id d75a77b69052e-4769b16d4fbso37506891cf.2
        for <kasan-dev@googlegroups.com>; Wed, 19 Mar 2025 08:09:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW/Khu6TsLcBgy47ZzrUiGKp3n+3xV6dBSuaAL3KD7ZLHQ78k7GVtJmvFraXQPiA7IwVFr8hMi+VG4=@googlegroups.com
X-Gm-Gg: ASbGncsLOsVrZNj0ysUr9Ta2I4smrt8haxPL2URPd/mmVw37EpuSEc+aAhvQC1CobrX
	rvVJYPN/dGn499kjTXHuZ5OLftPH9d3wZQoJiiNoWBjhGkNlfK2Qj/zHcQfhBabA2cw2xgpgRh8
	2zkcvDdE6Kqi40Eu/xM+bgLxnImlo=
X-Received: by 2002:a05:622a:551a:b0:476:9b40:c2cd with SMTP id
 d75a77b69052e-47708398fa0mr57614851cf.47.1742396939361; Wed, 19 Mar 2025
 08:08:59 -0700 (PDT)
MIME-Version: 1.0
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
 <20250319-sloppy-active-bonobo-f49d8e@leitao> <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
In-Reply-To: <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
From: "'Eric Dumazet' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Mar 2025 16:08:48 +0100
X-Gm-Features: AQ5f1JrR6wqlaMsojlFdR2Ql12vIjY5AFcPWOBEsZzIh_K1uGt-uCg2CYDO-r_8
Message-ID: <CANn89iKdJfkPrY1rHjzUn5nPbU5Z+VAuW5Le2PraeVuHVQ264g@mail.gmail.com>
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
To: paulmck@kernel.org
Cc: Breno Leitao <leitao@debian.org>, kuba@kernel.org, jhs@mojatatu.com, 
	xiyou.wangcong@gmail.com, jiri@resnulli.us, kuniyu@amazon.com, 
	rcu@vger.kernel.org, kasan-dev@googlegroups.com, netdev@vger.kernel.org
Content-Type: multipart/alternative; boundary="000000000000a16e930630b3661b"
X-Original-Sender: edumazet@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=scgNnQPU;       spf=pass
 (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::833
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

--000000000000a16e930630b3661b
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 19, 2025 at 4:04=E2=80=AFPM Paul E. McKenney <paulmck@kernel.or=
g> wrote:

> On Wed, Mar 19, 2025 at 07:56:40AM -0700, Breno Leitao wrote:
> > On Wed, Mar 19, 2025 at 03:41:37PM +0100, Eric Dumazet wrote:
> > > On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao <leitao@debian.o=
rg>
> wrote:
> > >
> > > > Hello,
> > > >
> > > > I am experiencing an issue with upstream kernel when compiled with
> debug
> > > > capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and
> > > > CONFIG_LOCKDEP plus a few others. You can find the full
> configuration at
> > > > ....
> > > >
> > > > Basically when running a `tc replace`, it takes 13-20 seconds to
> finish:
> > > >
> > > >         # time /usr/sbin/tc qdisc replace dev eth0 root handle
> 0x1234: mq
> > > >         real    0m13.195s
> > > >         user    0m0.001s
> > > >         sys     0m2.746s
> > > >
> > > > While this is running, the machine loses network access completely.
> The
> > > > machine's network becomes inaccessible for 13 seconds above, which
> is far
> > > > from
> > > > ideal.
> > > >
> > > > Upon investigation, I found that the host is getting stuck in the
> following
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
> > > >                 err =3D __tc_modify_qdisc(skb, n, extack, dev, tca,
> tcm,
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
> > > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle
> 0x1: mq
> > > > | grep \\$
> > > >         7) $ 4335849 us  |        } /* mq_init */
> > > >         7) $ 4339715 us  |      } /* qdisc_create */
> > > >         11) $ 15844438 us |        } /* mq_attach */
> > > >         11) $ 16129620 us |      } /* qdisc_graft */
> > > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> > > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> > > >
> > > >         In this case, the rtnetlink_rcv_msg() took 20 seconds, and,
> while
> > > > it
> > > >         was running, the NIC was not being able to send any packet
> > > >
> > > > Going one step further, this matches what I described above:
> > > >
> > > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> > > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle
> 0x1: mq
> > > > | grep "\\@\|\\$"
> > > >
> > > >         7) $ 4335849 us  |        } /* mq_init */
> > > >         7) $ 4339715 us  |      } /* qdisc_create */
> > > >         14) @ 210619.0 us |                      } /* schedule */
> > > >         14) @ 210621.3 us |                    } /* schedule_timeou=
t
> */
> > > >         14) @ 210654.0 us |                  } /*
> > > > wait_for_completion_state */
> > > >         14) @ 210716.7 us |                } /* __wait_rcu_gp */
> > > >         14) @ 210719.4 us |              } /* synchronize_rcu_norma=
l
> */
> > > >         14) @ 210742.5 us |            } /* synchronize_rcu */
> > > >         14) @ 144455.7 us |            } /* __qdisc_destroy */
> > > >         14) @ 144458.6 us |          } /* qdisc_put */
> > > >         <snip>
> > > >         2) @ 131083.6 us |                        } /* schedule */
> > > >         2) @ 131086.5 us |                      } /*
> schedule_timeout */
> > > >         2) @ 131129.6 us |                    } /*
> > > > wait_for_completion_state */
> > > >         2) @ 131227.6 us |                  } /* __wait_rcu_gp */
> > > >         2) @ 131231.0 us |                } /*
> synchronize_rcu_normal */
> > > >         2) @ 131242.6 us |              } /* synchronize_rcu */
> > > >         2) @ 152162.7 us |            } /* __qdisc_destroy */
> > > >         2) @ 152165.7 us |          } /* qdisc_put */
> > > >         11) $ 15844438 us |        } /* mq_attach */
> > > >         11) $ 16129620 us |      } /* qdisc_graft */
> > > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> > > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> > > >
> > > > From the stack trace, it appears that most of the time is spent
> waiting
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
> > >
> > > call_rcu() is asynchronous, this is very different from
> synchronize_rcu().
> >
> > That is a good point. The offender is synchronize_rcu() is here.
>
> Should that be synchronize_net()?
>

I think we should redesign lockdep_unregister_key() to work on a separately
allocated piece of memory,
then use kfree_rcu() in it.

Ie not embed a "struct lock_class_key" in the struct Qdisc, but a pointer t=
o

struct ... {
     struct lock_class_key;
     struct rcu_head  rcu;
}





>
>                                                         Thanx, Paul
>
> > > >         }
> > > >
> > > > So, from my newbie PoV, the issue can be summarized as follows:
> > > >
> > > >         netdev_lock_ops(dev);
> > > >         __tc_modify_qdisc()
> > > >           qdisc_graft()
> > > >             for (i =3D 0; i <  255; i++)
> > > >               qdisc_put()
> > > >                 ____qdisc_destroy()
> > > >                   call_rcu()
> > > >               }
> > > >
> > > > Questions:
> > > >
> > > > 1) I assume the egress traffic is blocked because we are modifying
> the
> > > >    qdisc, which makes sense. How is this achieved? Is it related to
> > > >    rtnl_lock?
> > > >
> > > > 2) Would it be beneficial to attempt qdisc_put() outside of the
> critical
> > > >    section (rtnl_lock?) to prevent this freeze?
> > > >
> > > >
> > >
> > > It is unclear to me why you have syncrhonize_rcu() calls.
> >
> > This is coming from:
> >
> >       __qdisc_destroy() {
> >               lockdep_unregister_key(&qdisc->root_lock_key) {
> >                       ...
> >                       /* Wait until is_dynamic_key() has finished
> accessing k->hash_entry. */
> >                       synchronize_rcu();
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANn89iKdJfkPrY1rHjzUn5nPbU5Z%2BVAuW5Le2PraeVuHVQ264g%40mail.gmail.com.

--000000000000a16e930630b3661b
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote g=
mail_quote_container"><div dir=3D"ltr" class=3D"gmail_attr">On Wed, Mar 19,=
 2025 at 4:04=E2=80=AFPM Paul E. McKenney &lt;<a href=3D"mailto:paulmck@ker=
nel.org">paulmck@kernel.org</a>&gt; wrote:<br></div><blockquote class=3D"gm=
ail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,=
204,204);padding-left:1ex">On Wed, Mar 19, 2025 at 07:56:40AM -0700, Breno =
Leitao wrote:<br>
&gt; On Wed, Mar 19, 2025 at 03:41:37PM +0100, Eric Dumazet wrote:<br>
&gt; &gt; On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao &lt;<a href=
=3D"mailto:leitao@debian.org" target=3D"_blank">leitao@debian.org</a>&gt; w=
rote:<br>
&gt; &gt; <br>
&gt; &gt; &gt; Hello,<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; I am experiencing an issue with upstream kernel when compile=
d with debug<br>
&gt; &gt; &gt; capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and<b=
r>
&gt; &gt; &gt; CONFIG_LOCKDEP plus a few others. You can find the full conf=
iguration at<br>
&gt; &gt; &gt; ....<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; Basically when running a `tc replace`, it takes 13-20 second=
s to finish:<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0# time /usr/sbin/tc qdisc r=
eplace dev eth0 root handle 0x1234: mq<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0real=C2=A0 =C2=A0 0m13.195s=
<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0user=C2=A0 =C2=A0 0m0.001s<=
br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0sys=C2=A0 =C2=A0 =C2=A00m2.=
746s<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; While this is running, the machine loses network access comp=
letely. The<br>
&gt; &gt; &gt; machine&#39;s network becomes inaccessible for 13 seconds ab=
ove, which is far<br>
&gt; &gt; &gt; from<br>
&gt; &gt; &gt; ideal.<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; Upon investigation, I found that the host is getting stuck i=
n the following<br>
&gt; &gt; &gt; call path:<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0__qdisc_destroy<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0mq_attach<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0qdisc_graft<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0tc_modify_qdisc<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0rtnetlink_rcv_msg<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netlink_rcv_skb<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netlink_unicast<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netlink_sendmsg<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; The big offender here is rtnetlink_rcv_msg(), which is calle=
d with<br>
&gt; &gt; &gt; rtnl_lock<br>
&gt; &gt; &gt; in the follow path:<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0static int tc_modify_qdisc(=
) {<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0...<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0netdev_lock_ops(dev);<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0err =3D __tc_modify_qdisc(skb, n, extack, dev, tca, tcm,<br>
&gt; &gt; &gt; &amp;replay);<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0netdev_unlock_ops(dev);<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0...<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0}<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; So, the rtnl_lock is held for 13 seconds in the case above. =
I also<br>
&gt; &gt; &gt; traced that __qdisc_destroy() is called once per NIC queue, =
totalling<br>
&gt; &gt; &gt; a total of 250 calls for the cards I am using.<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; Ftrace output:<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0# perf ftrace --graph-opts =
depth=3D100,tail,noirqs -G<br>
&gt; &gt; &gt; rtnetlink_rcv_msg=C2=A0 =C2=A0/usr/sbin/tc qdisc replace dev=
 eth0 root handle 0x1: mq<br>
&gt; &gt; &gt; | grep \\$<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A07) $ 4335849 us=C2=A0 |=C2=
=A0 =C2=A0 =C2=A0 =C2=A0 } /* mq_init */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A07) $ 4339715 us=C2=A0 |=C2=
=A0 =C2=A0 =C2=A0 } /* qdisc_create */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 15844438 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 } /* mq_attach */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 16129620 us |=C2=A0 =
=C2=A0 =C2=A0 } /* qdisc_graft */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 20469368 us |=C2=A0 =
=C2=A0 } /* tc_modify_qdisc */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 20470448 us |=C2=A0 }=
 /* rtnetlink_rcv_msg */<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0In this case, the rtnetlink=
_rcv_msg() took 20 seconds, and, while<br>
&gt; &gt; &gt; it<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0was running, the NIC was no=
t being able to send any packet<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; Going one step further, this matches what I described above:=
<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0# perf ftrace --graph-opts =
depth=3D100,tail,noirqs -G<br>
&gt; &gt; &gt; rtnetlink_rcv_msg=C2=A0 =C2=A0/usr/sbin/tc qdisc replace dev=
 eth0 root handle 0x1: mq<br>
&gt; &gt; &gt; | grep &quot;\\@\|\\$&quot;<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A07) $ 4335849 us=C2=A0 |=C2=
=A0 =C2=A0 =C2=A0 =C2=A0 } /* mq_init */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A07) $ 4339715 us=C2=A0 |=C2=
=A0 =C2=A0 =C2=A0 } /* qdisc_create */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210619.0 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* =
schedule */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210621.3 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* schedul=
e_timeout */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210654.0 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /*<br>
&gt; &gt; &gt; wait_for_completion_state */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210716.7 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __wait_rcu_gp */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210719.4 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu_normal */<br=
>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 210742.5 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 144455.7 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __qdisc_destroy */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A014) @ 144458.6 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* qdisc_put */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0&lt;snip&gt;<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131083.6 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 } /* schedule */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131086.5 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* =
schedule_timeout */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131129.6 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /*<br>
&gt; &gt; &gt; wait_for_completion_state */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131227.6 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __wait_rcu_gp =
*/<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131231.0 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu_norma=
l */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 131242.6 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* synchronize_rcu */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 152162.7 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* __qdisc_destroy */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02) @ 152165.7 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 } /* qdisc_put */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 15844438 us |=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 } /* mq_attach */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 16129620 us |=C2=A0 =
=C2=A0 =C2=A0 } /* qdisc_graft */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 20469368 us |=C2=A0 =
=C2=A0 } /* tc_modify_qdisc */<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A011) $ 20470448 us |=C2=A0 }=
 /* rtnetlink_rcv_msg */<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; From the stack trace, it appears that most of the time is sp=
ent waiting<br>
&gt; &gt; &gt; for the<br>
&gt; &gt; &gt; RCU grace period to free the qdisc (!?):<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0static void __qdisc_destroy=
(struct Qdisc *qdisc)<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0{<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0if (ops-&gt;destroy)<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0ops-&gt;destroy(qdisc);<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0call_rcu(&amp;qdisc-&gt;rcu, qdisc_free_cb);<br>
&gt; &gt; &gt;<br>
&gt; &gt; <br>
&gt; &gt; call_rcu() is asynchronous, this is very different from synchroni=
ze_rcu().<br>
&gt; <br>
&gt; That is a good point. The offender is synchronize_rcu() is here.<br>
<br>
Should that be synchronize_net()?<br></blockquote><div><br></div><div>I thi=
nk we should redesign lockdep_unregister_key() to work on a separately allo=
cated piece of memory,</div><div>then use kfree_rcu() in it.</div><div><br>=
</div><div>Ie not embed a &quot;struct lock_class_key&quot; in the struct Q=
disc, but a pointer to</div><div><br></div><div>struct ... {</div><div>=C2=
=A0 =C2=A0 =C2=A0struct lock_class_key;</div><div>=C2=A0 =C2=A0 =C2=A0struc=
t rcu_head=C2=A0 rcu;</div><div>}</div><div><br></div><div><br></div><div><=
br></div><div>=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"margin=
:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex"=
>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 Thanx, Paul<br>
<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0}<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; So, from my newbie PoV, the issue can be summarized as follo=
ws:<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0netdev_lock_ops(dev);<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0__tc_modify_qdisc()<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0qdisc_graft()<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0for (i =3D 0;=
 i &lt;=C2=A0 255; i++)<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0qdisc_=
put()<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0____qdisc_destroy()<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0call_rcu()<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0}<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; Questions:<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; 1) I assume the egress traffic is blocked because we are mod=
ifying the<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 qdisc, which makes sense. How is this achieved?=
 Is it related to<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 rtnl_lock?<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; 2) Would it be beneficial to attempt qdisc_put() outside of =
the critical<br>
&gt; &gt; &gt;=C2=A0 =C2=A0 section (rtnl_lock?) to prevent this freeze?<br=
>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;<br>
&gt; &gt; <br>
&gt; &gt; It is unclear to me why you have syncrhonize_rcu() calls.<br>
&gt; <br>
&gt; This is coming from:<br>
&gt; <br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0__qdisc_destroy() {<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0lockdep_unregist=
er_key(&amp;qdisc-&gt;root_lock_key) {<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0...<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0/* Wait until is_dynamic_key() has finished accessing k-&gt;ha=
sh_entry. */<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0synchronize_rcu();<br>
</blockquote></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CANn89iKdJfkPrY1rHjzUn5nPbU5Z%2BVAuW5Le2PraeVuHVQ264g%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CANn89iKdJfkPrY1rHjzUn5nPbU5Z%2BVAuW5Le2PraeVuHVQ264g%40mail=
.gmail.com</a>.<br />

--000000000000a16e930630b3661b--
