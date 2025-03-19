Return-Path: <kasan-dev+bncBCV7VV5FSADRBMMQ5S7AMGQEIXHAXFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 305C6A69778
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 19:08:51 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-47685de2945sf120097921cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 11:08:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742407730; cv=pass;
        d=google.com; s=arc-20240605;
        b=dd3XQmIar3k6K517z2RlXVweWw23/2ixZ9SuN5gIMAyWSPyXAQyu3DcyaAJOZbC0RF
         nJZXOnTjfbdeJEqS4PjON50a6iHT0B9syZnL5FS3lpxa6ah8Z5V6p8APvKrlcPlDNiYN
         +KtRrjq6a58vboDZAiJvCUeubGJjoX8mbYcN79CHD6yEm7tGugf1nNpxIdxeYVzA+3IP
         asGrCuyHRytgQsgyjQo2GAmeYXxyNhLwSGGpZlW+AWxtyHRBp1EgzRH1XqLDqDEm1VrV
         6hFh3BPJfaFQYvZdLLpM/wVKDyJQmUUGuasjL7oTly1EJXUPt+lTlTdLgjkVfBVDcGgO
         HWFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=pm/qDl4QcNofAHu7byBmE3txxICLo7GxHS5jwk0Pdvo=;
        fh=D0fxY4ASbmwA9FXT0iD2gknFc4sbOrl562RP2CG0hNI=;
        b=MKQSKctYJMWrRh9I5MeYFCVxBsFQwSlc/AzuuGk0UsEWiOjnpkDDSAQBxMFHi4dFsv
         Ar/UADkI6YygIhLbO3S2wtXvYyKu3QJAVfys9UQwyqFcYlFSPA72JVwMZy3OOkmkFxPL
         roEzD+MxSpqiP1FDHZ1rskPHC8plZIheA1DlBUvo07qKtaGLa5uQUr0Uhe1l8FwG8T6v
         99MNqNMmYD8PwBOYe1oBILr2sLyzdNhUNPpN+CYg9yfW6yOvSJpg0miYJv43iJCl6awe
         wZ5RlnEyaIbA4YvPo8B+98sIN+K3gKjl18KFfCo/vNZuB0HkYklKffaT5Cq6MHbiki06
         y2rQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lV3JRGlB;
       spf=pass (google.com: domain of xiyou.wangcong@gmail.com designates 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=xiyou.wangcong@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742407730; x=1743012530; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pm/qDl4QcNofAHu7byBmE3txxICLo7GxHS5jwk0Pdvo=;
        b=l7/r9Em3TcApbn1zqD6PVRfEpGpftnToBXVsb3m0LuibXM8u3EBMTxc5Js10PxhbcC
         /RgQWzFKeoPRoinn3CoC6KsMi1iIbkIqn7ud1KsYc8WuTVURRfhK5sKdHcrTmm746upN
         GI6msZmO+MusFjuLLjF38jsb+/JnO8v0CqPTnIcCIVJQYz7oTo/tpi3bcvfLRd5ZhLTj
         hHR6i6ActK7ugB45AcMMxFgpckaeytkZo0lPvuW+/hLUBmIX8AUhtEPYdoJ+kWa/uHrS
         ls/iyvBoHXqLi7UZLayptgPxWLG0ghk64g96XmUn5ACFzZbQyaD+rCDXY38HhalX27Rr
         aqxQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742407730; x=1743012530; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pm/qDl4QcNofAHu7byBmE3txxICLo7GxHS5jwk0Pdvo=;
        b=W8o/gv/irWzVXJ1OmMWYrft/5Jchadfmg7cgVnT8DZwpTDLManGb+NetCFv5hYn0b6
         Gx2KiT2X6NXHtzzB74a6yUljSwQbRLL7rbuug4SvzX1NGvhW2TkLxBG6XCzLLh2FTyH+
         x5NhBrJgcFiAp/2EFyEXI+BQ8PhcsvppAo+M8dWdIe05lMnXSoJm1ckKUVIUEEbNRjE/
         tpiHehuf9vlsST/gytaPuWIazK7GX8OUcovLRnI8SygUTugeQsvIe3/+9oQRpktQgToD
         AX7GjphkGxzbxTpE/VR56Wg+YI5/El4VPZaPIUFz8kK4G88voweNe62eZx5l3M/j5hTV
         PeAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742407730; x=1743012530;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pm/qDl4QcNofAHu7byBmE3txxICLo7GxHS5jwk0Pdvo=;
        b=Vnbs4gYE8b6l7E9Ad0YNgUtCdGk+ZJ08i3bJzvR513hPbbUQNpU78Psu8cO2YBYIlA
         ykGqlNAh8qfwJ7CAPRh9QjXhKgya10ic0Lk7huGXufJ5LoVhJYAbPaBAl5bY30DvoDI8
         nctesjhSSvw7d4wMgWeBFtDYooUzoFNrx423J8KHfMJXTX3ZMgG1T0Bz0rpeABMQnV6s
         mGULChSzb/1+FzzuqqJxsGun+tQUd3Fh8Eq7JW5+Mdc0x640qjsFSOpMm/AmAkBZc54l
         asr02C9I8qQ4dBZag7DbCpiQjFo2KNRKWFrVEr32P7bJFJii6d02sPXmT3JCBI4lCZFN
         KGWw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFdjv/KNafvxNW2jcslg1rjwyhVFyOgPqTLf9jL+DSeupcY1e/rSmkPjilTB86pbFXrubftQ==@lfdr.de
X-Gm-Message-State: AOJu0YxvIArjL2AOONTsp+fRahKVu1hr3Rylz8v0nxoSWcUa14inssJP
	Z9rndXZW5fg2NghKf+Dpill9NRAwlp816jy1HTemrFD/yUNTlYuS
X-Google-Smtp-Source: AGHT+IEAVinPfiKxwcjVaUrc2eYU4RKgu+XTCf0nP8uAvZElk+Ih2rnBrU6lTyDMCGlxinbfGytkxw==
X-Received: by 2002:a05:622a:4014:b0:476:8225:dad1 with SMTP id d75a77b69052e-47708335d52mr62065931cf.17.1742407729906;
        Wed, 19 Mar 2025 11:08:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJlvgZ8O6U0K/1557HwfvdTBTOOhzQrAMLY2a5EiKz16g==
Received: by 2002:ac8:7f94:0:b0:476:6bc3:c758 with SMTP id d75a77b69052e-47710f22e4bls2762941cf.0.-pod-prod-05-us;
 Wed, 19 Mar 2025 11:08:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVOcn/PpHFDhdHJlItcDkyfTgIzC3MceqQ7jnS7KYO+ufxqjRmLmqtS+t0AUbtoHAHkKeJ72hTX0as=@googlegroups.com
X-Received: by 2002:a05:620a:178f:b0:7c5:642f:b22c with SMTP id af79cd13be357-7c5a838ed24mr463501785a.20.1742407728805;
        Wed, 19 Mar 2025 11:08:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742407728; cv=none;
        d=google.com; s=arc-20240605;
        b=ex6Y0RSEhyhE49TwP+A1b28buCdss9qZhZMJYEHPtOKQ79IBXQ6zm2dnak36pdPi6G
         Ic+uRZOcBm7AEdkF3aNb0Ro4NO+FNGvGNmXSWo/L37Jfqd3hnr/LbrLJZJCQpiSGEnPH
         wUArleXJ+G3gLokastv/PXJ3bmvAScHsGtIDA2v98xPtfvghzhZx2pRbb4J04LFVuNGA
         u3aZJOcAw7eqLi7IkCYoCj40zT0K5OGHz2ZNeU2VOLQAZFAXUz99Pf/ujYwQYiHoS4Sp
         u0fbtk3D6ZtfUqpowvgK86y6oxQ+mx59l8SrzSv1rNcrmibRVfyVj1miD7+pkfk/XfYl
         EM4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Z2e+VASJvhMSdxri9GWf3DzgLKmwPUKxIoKmVo7qpYU=;
        fh=gC/pjP/b+00cqTtWLEo2Au70Rkplt4T04Lpsgf0Tk6s=;
        b=guk99E3dXhO59POeJMVKzPso/5lrgBvjHLSdRpOKduhtefVzSKxaeYdalsx//M9K9l
         C+PykJTNXaBjxRY8S1Y/Q56hPKcz0CEhsSrwVXMlOwGwm4UZ2Mm8EFAtRq0+3/lIVutU
         cbX4i9yqmDGNBg2/m5mZ0zLgTlPtVPsKeNdlVkY+c61WmimUq/Sr7rYhJkrU5b5ys65F
         yq/dAURw7R8WZNSA8muQCblwo9luXQuvu/hXEttGO3hlUNx8YBeIU1xUMLqDnO9qtHRM
         ynR1mvVxEfzgbVlXSAIuuCqiC5DRYEvuyhShfjh8EP8asjyu9D/SS3kAVbZ9HQXk5/68
         2hIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lV3JRGlB;
       spf=pass (google.com: domain of xiyou.wangcong@gmail.com designates 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=xiyou.wangcong@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ua1-x92a.google.com (mail-ua1-x92a.google.com. [2607:f8b0:4864:20::92a])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c573be43c9si64998485a.4.2025.03.19.11.08.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Mar 2025 11:08:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of xiyou.wangcong@gmail.com designates 2607:f8b0:4864:20::92a as permitted sender) client-ip=2607:f8b0:4864:20::92a;
Received: by mail-ua1-x92a.google.com with SMTP id a1e0cc1a2514c-86112ab1ad4so2917898241.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Mar 2025 11:08:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWRqONA3kJ7xbhAcJKr3X3jz+at+A8fghxK4HavC3bL3vg72wuhYMpWNP4QcgLy3c6SO/j11iYlabM=@googlegroups.com
X-Gm-Gg: ASbGncuh+ZKLPTUQZUMX35h3uj5+0PsprEfU6nVkUt38YkUvs2mTfeY0kLPxlF4WEYD
	zTZej4ObZWupXksbCxFBFV082VRM40sebYnitGU9GVW1PdcasweQnqhPUNV9ux+8HxcUqauT492
	VAVwnQYGVbHwuUTqFl+0F5kxOqYNV4eVxPVDR44mI=
X-Received: by 2002:a05:6122:6142:b0:518:865e:d177 with SMTP id
 71dfb90a1353d-52589291044mr3030042e0c.9.1742407728320; Wed, 19 Mar 2025
 11:08:48 -0700 (PDT)
MIME-Version: 1.0
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
 <20250319-sloppy-active-bonobo-f49d8e@leitao> <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
 <CANn89iKdJfkPrY1rHjzUn5nPbU5Z+VAuW5Le2PraeVuHVQ264g@mail.gmail.com>
In-Reply-To: <CANn89iKdJfkPrY1rHjzUn5nPbU5Z+VAuW5Le2PraeVuHVQ264g@mail.gmail.com>
From: Cong Wang <xiyou.wangcong@gmail.com>
Date: Wed, 19 Mar 2025 11:08:35 -0700
X-Gm-Features: AQ5f1Jrq2PDQGCyCHQKcD4stIBbEhDXypryz1JKQj6Skn3GDIZXnBW7_5Um-J80
Message-ID: <CAM_iQpVe+dscK_6hRnTMc_6QjGiBHX0gtaDiwfxggD7tgccbsg@mail.gmail.com>
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
To: Eric Dumazet <edumazet@google.com>
Cc: paulmck@kernel.org, Breno Leitao <leitao@debian.org>, kuba@kernel.org, 
	jhs@mojatatu.com, jiri@resnulli.us, kuniyu@amazon.com, rcu@vger.kernel.org, 
	kasan-dev@googlegroups.com, netdev@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: xiyou.wangcong@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lV3JRGlB;       spf=pass
 (google.com: domain of xiyou.wangcong@gmail.com designates
 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=xiyou.wangcong@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Mar 19, 2025 at 8:08=E2=80=AFAM Eric Dumazet <edumazet@google.com> =
wrote:
>
>
>
> On Wed, Mar 19, 2025 at 4:04=E2=80=AFPM Paul E. McKenney <paulmck@kernel.=
org> wrote:
>>
>> On Wed, Mar 19, 2025 at 07:56:40AM -0700, Breno Leitao wrote:
>> > On Wed, Mar 19, 2025 at 03:41:37PM +0100, Eric Dumazet wrote:
>> > > On Wed, Mar 19, 2025 at 2:09=E2=80=AFPM Breno Leitao <leitao@debian.=
org> wrote:
>> > >
>> > > > Hello,
>> > > >
>> > > > I am experiencing an issue with upstream kernel when compiled with=
 debug
>> > > > capabilities. They are CONFIG_DEBUG_NET, CONFIG_KASAN, and
>> > > > CONFIG_LOCKDEP plus a few others. You can find the full configurat=
ion at
>> > > > ....
>> > > >
>> > > > Basically when running a `tc replace`, it takes 13-20 seconds to f=
inish:
>> > > >
>> > > >         # time /usr/sbin/tc qdisc replace dev eth0 root handle 0x1=
234: mq
>> > > >         real    0m13.195s
>> > > >         user    0m0.001s
>> > > >         sys     0m2.746s
>> > > >
>> > > > While this is running, the machine loses network access completely=
. The
>> > > > machine's network becomes inaccessible for 13 seconds above, which=
 is far
>> > > > from
>> > > > ideal.
>> > > >
>> > > > Upon investigation, I found that the host is getting stuck in the =
following
>> > > > call path:
>> > > >
>> > > >         __qdisc_destroy
>> > > >         mq_attach
>> > > >         qdisc_graft
>> > > >         tc_modify_qdisc
>> > > >         rtnetlink_rcv_msg
>> > > >         netlink_rcv_skb
>> > > >         netlink_unicast
>> > > >         netlink_sendmsg
>> > > >
>> > > > The big offender here is rtnetlink_rcv_msg(), which is called with
>> > > > rtnl_lock
>> > > > in the follow path:
>> > > >
>> > > >         static int tc_modify_qdisc() {
>> > > >                 ...
>> > > >                 netdev_lock_ops(dev);
>> > > >                 err =3D __tc_modify_qdisc(skb, n, extack, dev, tca=
, tcm,
>> > > > &replay);
>> > > >                 netdev_unlock_ops(dev);
>> > > >                 ...
>> > > >         }
>> > > >
>> > > > So, the rtnl_lock is held for 13 seconds in the case above. I also
>> > > > traced that __qdisc_destroy() is called once per NIC queue, totall=
ing
>> > > > a total of 250 calls for the cards I am using.
>> > > >
>> > > > Ftrace output:
>> > > >
>> > > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
>> > > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handl=
e 0x1: mq
>> > > > | grep \\$
>> > > >         7) $ 4335849 us  |        } /* mq_init */
>> > > >         7) $ 4339715 us  |      } /* qdisc_create */
>> > > >         11) $ 15844438 us |        } /* mq_attach */
>> > > >         11) $ 16129620 us |      } /* qdisc_graft */
>> > > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
>> > > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
>> > > >
>> > > >         In this case, the rtnetlink_rcv_msg() took 20 seconds, and=
, while
>> > > > it
>> > > >         was running, the NIC was not being able to send any packet
>> > > >
>> > > > Going one step further, this matches what I described above:
>> > > >
>> > > >         # perf ftrace --graph-opts depth=3D100,tail,noirqs -G
>> > > > rtnetlink_rcv_msg   /usr/sbin/tc qdisc replace dev eth0 root handl=
e 0x1: mq
>> > > > | grep "\\@\|\\$"
>> > > >
>> > > >         7) $ 4335849 us  |        } /* mq_init */
>> > > >         7) $ 4339715 us  |      } /* qdisc_create */
>> > > >         14) @ 210619.0 us |                      } /* schedule */
>> > > >         14) @ 210621.3 us |                    } /* schedule_timeo=
ut */
>> > > >         14) @ 210654.0 us |                  } /*
>> > > > wait_for_completion_state */
>> > > >         14) @ 210716.7 us |                } /* __wait_rcu_gp */
>> > > >         14) @ 210719.4 us |              } /* synchronize_rcu_norm=
al */
>> > > >         14) @ 210742.5 us |            } /* synchronize_rcu */
>> > > >         14) @ 144455.7 us |            } /* __qdisc_destroy */
>> > > >         14) @ 144458.6 us |          } /* qdisc_put */
>> > > >         <snip>
>> > > >         2) @ 131083.6 us |                        } /* schedule */
>> > > >         2) @ 131086.5 us |                      } /* schedule_time=
out */
>> > > >         2) @ 131129.6 us |                    } /*
>> > > > wait_for_completion_state */
>> > > >         2) @ 131227.6 us |                  } /* __wait_rcu_gp */
>> > > >         2) @ 131231.0 us |                } /* synchronize_rcu_nor=
mal */
>> > > >         2) @ 131242.6 us |              } /* synchronize_rcu */
>> > > >         2) @ 152162.7 us |            } /* __qdisc_destroy */
>> > > >         2) @ 152165.7 us |          } /* qdisc_put */
>> > > >         11) $ 15844438 us |        } /* mq_attach */
>> > > >         11) $ 16129620 us |      } /* qdisc_graft */
>> > > >         11) $ 20469368 us |    } /* tc_modify_qdisc */
>> > > >         11) $ 20470448 us |  } /* rtnetlink_rcv_msg */
>> > > >
>> > > > From the stack trace, it appears that most of the time is spent wa=
iting
>> > > > for the
>> > > > RCU grace period to free the qdisc (!?):
>> > > >
>> > > >         static void __qdisc_destroy(struct Qdisc *qdisc)
>> > > >         {
>> > > >                 if (ops->destroy)
>> > > >                         ops->destroy(qdisc);
>> > > >
>> > > >                 call_rcu(&qdisc->rcu, qdisc_free_cb);
>> > > >
>> > >
>> > > call_rcu() is asynchronous, this is very different from synchronize_=
rcu().
>> >
>> > That is a good point. The offender is synchronize_rcu() is here.
>>
>> Should that be synchronize_net()?
>
>
> I think we should redesign lockdep_unregister_key() to work on a separate=
ly allocated piece of memory,
> then use kfree_rcu() in it.
>
> Ie not embed a "struct lock_class_key" in the struct Qdisc, but a pointer=
 to

Lockdep requires the key object must be static:

 822 /*
 823  * Is this the address of a static object:
 824  */
 825 #ifdef __KERNEL__
 826 static int static_obj(const void *obj)
 827 {
 828         unsigned long addr =3D (unsigned long) obj;
 829
 830         if (is_kernel_core_data(addr))
 831                 return 1;
 832
 833         /*
 834          * keys are allowed in the __ro_after_init section.
 835          */
 836         if (is_kernel_rodata(addr))
 837                 return 1;
 838

I am afraid the best suggestion here would be just disabling LOCKDEP,
which is known for big overhead.

Thanks.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AM_iQpVe%2BdscK_6hRnTMc_6QjGiBHX0gtaDiwfxggD7tgccbsg%40mail.gmail.com.
