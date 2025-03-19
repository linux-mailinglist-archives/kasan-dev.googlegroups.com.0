Return-Path: <kasan-dev+bncBCS4VDMYRUNBBF525O7AMGQEOGOJRVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 13A01A6923B
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 16:04:57 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-2c2d24b3947sf626669fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 08:04:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742396695; cv=pass;
        d=google.com; s=arc-20240605;
        b=BtlAyIvjdwQmYnQCJKBw2PfhcOSJJIf+ATO8WwWKcU4f6rOZPyUJEvaMOAfEmTXkl1
         7SEgO6vnDcuLKtiLmMxjjgIF9P+kqY8zwkIRNYZzM1KlqYCL+SE08HOBW91pDVzXqkZ2
         l/SdtSgcTyQerrlno6+ZNVvj13ClGGjXu+ANbvT3xUIDgY/INKzjBFl1WQ9Sz+OfIU0O
         tPTQyTb4IZiZDx7Ok1t68ebK/KFCmjxV8PiwW6C9CSpH52VJXZRqQiZ7boU9cYb4XjtH
         FuYWXTSFL9g1WLzbg2ubc1WC8wIW1dJUwS4bWBBfvhV1GvM/lFPUAIWQ+lup+7VYgoYR
         rxFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=pleOKvFvmIhp9gglJ5Y821Ktcyoyg713vBpiSExPnok=;
        fh=OEo07yZ6FjGMGmvIDvXN7kF/OknNsrJjAoE32OZlptc=;
        b=Wdh4ZSICULpnFQ5kbKnQP2deu4rqMFz73KlsJZNUzoPDdud5vMerZ6RZkuJeGLDDa0
         EkpxMpG530zhWrayu9eZHv4w64xWeOwpVZGIis+oV112JRi6zxjT0jeUzg+HTulqxszc
         xRJgSVImyTY/l6L0doEfPjrfLyhQqSaQEGD4OMjW2nmGYjoKvWxAtH5so6I9Xrrsi//i
         gF55hNggDdpJghhLl+EgeqKXbgrbW1XRgZVPs4rvH+bhBpGLrUO8b4ddJ/Hh/cF5158q
         S52QLJVioQoqZMc47S66IeyRyTA+GbWkOTBk6RSTOsouZ1rIRTu/fX/ebmn00TjVpfdI
         oEBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=it2L9jiC;
       spf=pass (google.com: domain of srs0=en1s=wg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=eN1s=WG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742396695; x=1743001495; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=pleOKvFvmIhp9gglJ5Y821Ktcyoyg713vBpiSExPnok=;
        b=omh0APwmHVDW87DuqjJPOKuunfH7jfqUTdsrjXYzY98wMi0HdzZoF5h6c8QTzuA3SK
         N8i+YV1PmK6Hu+O9Uu0j7azvyNCcrfuK0FoTY2Wtl4saHS3wjpNTDbl06uOo2HYEonZj
         d82178FF1i8aQvbcIm8qUYnIXhQoJg+2+gByDcLIJds2HdtdONBnHC8w/WFqVR/VTe5y
         xgJ9uNp/MmtZtbP8rgWQSLwcUOkLTXmjqYhRqOa3KCCcL2ZD3ta4yhv3Q1FZ6zDT5k42
         jzpEcDwyjAeJjfwYsZwJa/T030DvCWD7Qf9UTGQ11gxlaPoBrFP0ZnfAHGwpKCac9Uj2
         uzCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742396695; x=1743001495;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=pleOKvFvmIhp9gglJ5Y821Ktcyoyg713vBpiSExPnok=;
        b=JtuEmJMWHcormKMORysnWJu4FpipLxb5nVcCuPY34M9UVdc5zd/h9Ry/SmlC3PjQMg
         i2LuNSkKGY9adTWL6M8N68ZrGQj/Rz+mqRrU5kx+B7pEMDnJNgaZquWUtZmzSXiFQEZI
         RmBJ/H7FdjaElAhl0Rdtsw6PjPs541Jlq/DajtpPzUo9oEmGduyUlH/RXgLA5lbQLO69
         vtVRUiLFOproxWcBMXgfv49kSDbvLx2F8xetg3H5YqK+0n3pK0hAP0MWfUhK+7sLqKkl
         13NYpk8Kh3rERKEtfxaxgnCl/QMvjY0v1bmhXITbRuO3feBGka+wFegXL/WHGGqU4H+m
         AqCg==
X-Forwarded-Encrypted: i=2; AJvYcCVjJ6m2uD6PDVwtnTK+F0yo1IVl5DCo8fKuistWVx2X2KtoW8zMN/cnTC6ZQ2gs2zqPWmVs1Q==@lfdr.de
X-Gm-Message-State: AOJu0YxE5GsDRRt6GA1I3TSjzFDaZg+9eJESXiliiXvZXYX8h0rIAqnL
	hjtdsIT+Q33+nuQ6F5WHzkcqPkC5fHCymkcTzCtMrQzG2rfGprLR
X-Google-Smtp-Source: AGHT+IETB9IJnx1KqjkL9eycwGDioLYAd000DwkxdvEoQnVlgBwYDqBL5ijCGZfgFpeVqobjYePE8w==
X-Received: by 2002:a05:6871:5821:b0:2b8:8d81:4658 with SMTP id 586e51a60fabf-2c719c2b2aemr4422651fac.2.1742396695375;
        Wed, 19 Mar 2025 08:04:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIF5bqQwUcs8MVd/ew2dZ2geA1+RmVcSYLspLHiReAUCw==
Received: by 2002:a05:6871:e48:b0:2c2:384e:1c12 with SMTP id
 586e51a60fabf-2c6abc28a88ls868076fac.0.-pod-prod-00-us; Wed, 19 Mar 2025
 08:04:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJfWkAtpD2lgvfqXo7uaevlitZcqbcOaBL4otTjN8O3WtnMJhRgrt1siLbaBXZ8+kiQUoiBbU4HsY=@googlegroups.com
X-Received: by 2002:a05:6830:398c:b0:72b:8f4e:8c67 with SMTP id 46e09a7af769-72bfc17abccmr2554488a34.13.1742396693222;
        Wed, 19 Mar 2025 08:04:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742396693; cv=none;
        d=google.com; s=arc-20240605;
        b=isyeMnP62G/lOdC9J3RQwrY0Zrko5ucOvHLVnIpm+ZHgakYgxpDyE3YDIc70AcIo/t
         DL0yuu5gwKtxL8L6kpv8vIbqV+6HoX/Jh2JDYR7rI3G0V16POaqCazLaqMlxNEcGNLhv
         ODACdKFGbjJEIEvrQgT3LF7cLERHmueTSpqFImi/19noqjWWo+3vNocgEPzSlRVHgEd+
         BydZl4aNLJNws3Lmo+gXgqf6NjTIXsJpYorPsSX8OaOWfhQxabVqWCKhBRH9RbekKkld
         miuL7I07kqNcnTyGG3EBSjsD4lwhpNbrGjSqw5KdZV+4WrtOw9PCCBWbqjyPIvlXZHIg
         vJAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=B7tDrNCLGoWNjx8KJacZAAlSKJPL2DVrkwvZvsc/hBU=;
        fh=GHryicin8k8HzqfCgyCWrbu3u9gdhsDvf5qklFD0SrQ=;
        b=Ws0LnzLMVmqpoSavn1dO1EGuSLQccX1axpokbLMJQKrBcdLbvCvSpEAa7pG8miv4g1
         nVK+P2suBIb7mdCZVA8jBTVDId+0wy5ggE7mAvX3mUqKk6osNZTWrrz53mxGJySJdBPf
         qqW8IOLE1ELtdS7Ln2Ij1bOoEPiBHPEbHRx7MGqJavmEwMKHi43w3AU4moZJxRLo9Y7Q
         hFDNkbRyjO/goNWh+w+Z7qkVx/+f8aFceoTsltpdRY8FoW/ztA2cyaccYBBNlhBl6lBS
         fY++NVjQK2X3ogth7kaMOgiA4ALX3GTOkmyddSYLEzzI8o4RGXth0JCkpzIEs8tuKUdg
         X8WQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=it2L9jiC;
       spf=pass (google.com: domain of srs0=en1s=wg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=eN1s=WG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-72bb275e9e5si510286a34.5.2025.03.19.08.04.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Mar 2025 08:04:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=en1s=wg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 0637F5C0528;
	Wed, 19 Mar 2025 15:02:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 93BCDC4CEE8;
	Wed, 19 Mar 2025 15:04:52 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 40313CE0BC5; Wed, 19 Mar 2025 08:04:52 -0700 (PDT)
Date: Wed, 19 Mar 2025 08:04:52 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Breno Leitao <leitao@debian.org>
Cc: Eric Dumazet <edumazet@google.com>, kuba@kernel.org, jhs@mojatatu.com,
	xiyou.wangcong@gmail.com, jiri@resnulli.us, kuniyu@amazon.com,
	rcu@vger.kernel.org, kasan-dev@googlegroups.com,
	netdev@vger.kernel.org
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
Message-ID: <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
 <20250319-sloppy-active-bonobo-f49d8e@leitao>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250319-sloppy-active-bonobo-f49d8e@leitao>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=it2L9jiC;       spf=pass
 (google.com: domain of srs0=en1s=wg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=eN1s=WG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Wed, Mar 19, 2025 at 07:56:40AM -0700, Breno Leitao wrote:
> On Wed, Mar 19, 2025 at 03:41:37PM +0100, Eric Dumazet wrote:
> > On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao <leitao@debian.org=
> wrote:
> >=20
> > > Hello,
> > >
> > > I am experiencing an issue with upstream kernel when compiled with de=
bug
> > > capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and
> > > CONFIG_LOCKDEP plus a few others. You can find the full configuration=
 at
> > > ....
> > >
> > > Basically when running a `tc replace`, it takes 13-20 seconds to fini=
sh:
> > >
> > >         # time /usr/sbin/tc qdisc replace dev eth0 root handle 0x1234=
: mq
> > >         real    0m13.195s
> > >         user    0m0.001s
> > >         sys     0m2.746s
> > >
> > > While this is running, the machine loses network access completely. T=
he
> > > machine's network becomes inaccessible for 13 seconds above, which is=
 far
> > > from
> > > ideal.
> > >
> > > Upon investigation, I found that the host is getting stuck in the fol=
lowing
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
> > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle 0=
x1: mq
> > > | grep \\$
> > >         7) $ 4335849 us  |        } /* mq_init */
> > >         7) $ 4339715 us  |      } /* qdisc_create */
> > >         11) $ 15844438 us |        } /* mq_attach */
> > >         11) $ 16129620 us |      } /* qdisc_graft */
> > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
> > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
> > >
> > >         In this case, the rtnetlink_rcv_msg() took 20 seconds, and, w=
hile
> > > it
> > >         was running, the NIC was not being able to send any packet
> > >
> > > Going one step further, this matches what I described above:
> > >
> > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
> > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handle 0=
x1: mq
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
> > >         2) @ 131086.5 us |                      } /* schedule_timeout=
 */
> > >         2) @ 131129.6 us |                    } /*
> > > wait_for_completion_state */
> > >         2) @ 131227.6 us |                  } /* __wait_rcu_gp */
> > >         2) @ 131231.0 us |                } /* synchronize_rcu_normal=
 */
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
> >=20
> > call_rcu() is asynchronous, this is very different from synchronize_rcu=
().
>=20
> That is a good point. The offender is synchronize_rcu() is here.

Should that be synchronize_net()?

							Thanx, Paul

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
> > > 2) Would it be beneficial to attempt qdisc_put() outside of the criti=
cal
> > >    section (rtnl_lock?) to prevent this freeze?
> > >
> > >
> >=20
> > It is unclear to me why you have syncrhonize_rcu() calls.
>=20
> This is coming from:
>=20
> 	__qdisc_destroy() {
> 		lockdep_unregister_key(&qdisc->root_lock_key) {
> 			...
> 			/* Wait until is_dynamic_key() has finished accessing k->hash_entry. *=
/
> 			synchronize_rcu();

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5=
e0527e8-c92e-4dfb-8dc7-afe909fb2f98%40paulmck-laptop.
