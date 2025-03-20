Return-Path: <kasan-dev+bncBDTMJ55N44FBBDWI6G7AMGQEWY7YTLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B460A6AD5A
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 19:53:04 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-43d3b211d0esf12432535e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 11:53:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742496783; cv=pass;
        d=google.com; s=arc-20240605;
        b=f6+BYCeNFG/z2Vmm2VH7kk5wCIDAXHuRVoSG/sRfJlJeTRvz3QykfzGFJyy5uXXR6e
         npmFdCoOd/0z1qRbN8HpJmiVJQ3MGMOPd1ztggubSpwiwIwcCihdEhOuPdqTXnJ5DKba
         K3UcnIYSHdRGOdgz+vb1d2wb2hBQDkDqprfIEBTiqWr3VMpEkv/gp9Y3HKPv9JRZDGVB
         bbgKbtAkpsX1nG27vlRMLM20L3HjqC9Tv9FYu3w1ReQGs09qNDIF8o+lQGccrL5wqgqy
         QfS7/G+Zi3kDcQ+Nr0tA/Yc6W+QhExAgHRW0rUy7z6jD2r31U/iaEDcERDJpNLDnviba
         9kgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=LGsw45uutlqawFddnxfFKH8qGUiKRG1yWblFW1Q2Qog=;
        fh=Qyv4Zr7hHfNrM4frbMqDj5KufqQzubkpO8jdW1WBzNM=;
        b=IasyaNZiZ87J/jBZUK/HrolmdSua/QSUuwvbfaB8qkES/CrVmjfl22dcYKLFapEP4Z
         7Ja25IsgLs5CqZaRfX41aapRzexX+6OmnO99upkBaLQjD6fnkZc6+eMseqXvtMb8NZZF
         al5yJ1qjn8EghHLMfMFfbgJa9ro5918Uc9+VqmR74gw2v/q9GDsYdD1F5JFfLb9P9Gnm
         uYDkZ+B5Y2vNk5YITwXOwIbAhgD/I+GPpPlAeoR1YXFXJrJMBxuV7z/c4sNFklwcVoRB
         uHZtYteMdL9jifrnoFj3wIv9aeRR/d7RbNKAZoCUB07BjXAk2gAIT2yki0Mka9QeTOLa
         umSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.42 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742496783; x=1743101583; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LGsw45uutlqawFddnxfFKH8qGUiKRG1yWblFW1Q2Qog=;
        b=pqW6hqtDr5bZEukuVW6XIn/Ttu6/3m7ClMl3+7zA3Pj6b5P0+CS+L4h9XH3YqxsP8f
         ehrfqL+CWsN4RtI7jOmgTBmX4rhqrP0IJd2vhelz47cLQFbB5lYsZsqcdn4i3uYGf1tP
         w8ydbZnY21OiMJRYzoOhM92N0h1RifbGymrbp55itVDB/n1dgYpjZ+ApwgknBk8a38I3
         7rn2sPB1ZTcoW6PPMgRc+kGlIpI2jbMnzF9ff+po4jGVduJ2ehpdHohMXpIzUK55kPvv
         Z3tveOgsb6C2bYUqBV1Z+BFzM5NwA8PyDEyXPu0qSv6sJs2y/92bElOhcN2vUCV98yxq
         jUAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742496783; x=1743101583;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LGsw45uutlqawFddnxfFKH8qGUiKRG1yWblFW1Q2Qog=;
        b=e6IHHgVhe7bJsi85XhnI1F10yVszrBZ2tYGYDlsyLfQtZ4Puhjm372rkF3PmSC+dHG
         /LlrNRBd0/rq7jFgW5bNXh5/l0QYJ6qxvxeL5LVWg6sfDcvcXbo35ZslnOLcYKnf6S1x
         fHlS6c6xVNdpFnBnxKspHtl3LMeoN6IqrHlvy5xD+CXLOxr/6EtBhnFegzdxH18LC3LZ
         lOMAUcUCM+Nl8Mhh6T8RRnnYfW5cKxsyUJk8U3IOFbDf1JpHRSAxZXUwOSwp9+Q2nEwa
         VyF03L3eCEJOgUQJ2XxlNEuuNsOoZycwHjs9Cej3ahqPnZOCKQ1HfCIOGFH/X1UsYNOa
         lk9g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX0F9TzzlBu2iwY/d3PAq9MKWmBcn45hIUt10ex7Rx+uHR0o3UdP4ylzV8VD37U4fh0qZeERg==@lfdr.de
X-Gm-Message-State: AOJu0YwixJ864sNty98jJpbABggOXlRlfjzwFWxvgUEHDEvdG3xO2Q9m
	jEK+jyrQN4OgHjQAoORQnxCPYmByrEii23dQuJNeQHY55lUADRT2
X-Google-Smtp-Source: AGHT+IH5Q5y69XKUBrsh8WtHkrZDIEGUoXRZjM93+5TzsEFOAuF7JZlPAuypyf4W208ueg2gBnLz+g==
X-Received: by 2002:a05:600c:42ca:b0:43c:f680:5c2e with SMTP id 5b1f17b1804b1-43d491be155mr37988115e9.13.1742496783099;
        Thu, 20 Mar 2025 11:53:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJzsjwLt7/61qhDP685Be+JVih7gNBaG8l+bsB++0miHQ==
Received: by 2002:a05:600c:1c0d:b0:43c:f182:cc48 with SMTP id
 5b1f17b1804b1-43d491afcd4ls3095845e9.2.-pod-prod-00-eu; Thu, 20 Mar 2025
 11:53:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVHt8oQmzsUbtXhDjrUgJ9HcAH4d2EnAE6LMAbxuIRjkaL6fWH/zYwwwt0poPRaVsY7uOYkms/VWT4=@googlegroups.com
X-Received: by 2002:a05:600c:4689:b0:43b:c305:3954 with SMTP id 5b1f17b1804b1-43d491723c4mr43181775e9.8.1742496779975;
        Thu, 20 Mar 2025 11:52:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742496779; cv=none;
        d=google.com; s=arc-20240605;
        b=eMovkRuDq9yvbKhlIwHsEd2rEzvtGxe0EuIrZ+XpBAP0Gg/RGw8dyuL4mFx+O+1mSC
         7m1zZSVW1MA67ieE/YM0WEICvmoTthaxJnrBSgD6+Mp6C7fkHXmtBPjl/E4br7u+C03F
         Oajc5+RApV2Ngeybh7gEit3Vbl5Y+ZTHbCFDRDo2s/aF2Qp6sjjGd9PtpqXh1Wc961Na
         rE7+4tNfyFxU5ij/MpVkPLvpjAdtEVNGKQn4hcIuTFhPVrf4d88nPV6o97K0TcB3MFeI
         /L5jfH8vlPNnCNWF2J6D4HbNeCSfUrNvbesrjCtH5ksYQvayO+ur6g6eocnmDXWVR0GF
         6gcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=k/CXK/lkCmDZhi01vUA4HT1uCVDUJUDuW4LmxwM3DFY=;
        fh=qHtMDQCSMoIkz2F6HvBV//BU2lCliyNNPrtJ8wiLOmE=;
        b=So0gW3HtgsaiVy28CzcPbmKt3Ex7E1LMz6KdT7wxQrVlvjx+FscJEjiLd5UhUBvSE6
         4LhSkGyLhSe4U4DxBCp03ZtVaxH8wEQD3/YXU2bnigWf6uvkb44Dv1Q/4rjwDDBASruO
         IEXhIARPQPLFT79XPOvt4cV4kIJJ+Tt+yMMh25dZqjK380L2z4vkVn1zMTPZ0AS4u8HU
         y4IgJ2/1T0YOQeXNqYYhnGfWGn3H8zb+8ZoGGS07NNgUK+h/K6gFEdaYluowL+j5ihAG
         EjSkjoxmwkaZEkooO+oeeQolLIJ2IckkaJpySWcloCaf0LItDF+QFKIoHgTacxHZFA02
         xnkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.42 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ed1-f42.google.com (mail-ed1-f42.google.com. [209.85.208.42])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d3b9d272bsi5583995e9.1.2025.03.20.11.52.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Mar 2025 11:52:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.42 as permitted sender) client-ip=209.85.208.42;
Received: by mail-ed1-f42.google.com with SMTP id 4fb4d7f45d1cf-5e5deb6482cso4446085a12.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Mar 2025 11:52:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVxnh3QV3Msxjt8lTS+LrEvgwo9PdIKUZkTvoqHuqaac6xjOAfOXmaOti7fGTEZJqXqnrJc9XGIdqk=@googlegroups.com
X-Gm-Gg: ASbGncujkGheDVPC9SMKMrl9YVuQWv0LMYIJaoawZNtMXo/j2wd6szj+yy/e2zgTkbU
	15BJfbEzboGbvjCA0wTTYUcpVbSMJ/E1ZAUfjxMz7UMdz7s5UAaPoJoF8gGDRn+oZOCWtglR4t9
	HLoo4qUc8TTGJXYt5SjhFmMJ7SM9StVcnLHZMw4sqeC9bFvK6WsSBEkizKOdzguur1UITFkCXk5
	jTXW8ROnHrZtoAaVNkbbiNUSq/VJ8Ml7fs1T0PsITB5/DA6fEVu7OVzL6gAwFoKG/DMMLGDe/nh
	12W+cZ9apQBfYDs9f77J3uA2jWsSnzK4
X-Received: by 2002:a17:906:dc8e:b0:ac1:17fe:c74f with SMTP id a640c23a62f3a-ac3f03c1e7emr51087466b.21.1742496779175;
        Thu, 20 Mar 2025 11:52:59 -0700 (PDT)
Received: from gmail.com ([2a03:2880:30ff::])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ac3efd4d36csm21371066b.170.2025.03.20.11.52.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Mar 2025 11:52:58 -0700 (PDT)
Date: Thu, 20 Mar 2025 11:52:56 -0700
From: Breno Leitao <leitao@debian.org>
To: Jamal Hadi Salim <jhs@mojatatu.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, longman@redhat.com,
	bvanassche@acm.org, Eric Dumazet <edumazet@google.com>,
	kuba@kernel.org, xiyou.wangcong@gmail.com, jiri@resnulli.us,
	kuniyu@amazon.com, rcu@vger.kernel.org, kasan-dev@googlegroups.com,
	netdev@vger.kernel.org
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
Message-ID: <20250320-demonic-marmoset-of-economy-bba7ed@leitao>
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
 <20250319-sloppy-active-bonobo-f49d8e@leitao>
 <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
 <CANn89iKdJfkPrY1rHjzUn5nPbU5Z+VAuW5Le2PraeVuHVQ264g@mail.gmail.com>
 <0e9dbde7-07eb-45f1-a39c-6cf76f9c252f@paulmck-laptop>
 <20250319-truthful-whispering-moth-d308b4@leitao>
 <CAM0EoM=NJEeCcDdJ5kp0e8iyRG1LmvfzvBVpb2Mq5zP+QcvmMg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAM0EoM=NJEeCcDdJ5kp0e8iyRG1LmvfzvBVpb2Mq5zP+QcvmMg@mail.gmail.com>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.208.42 as
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

Hello Jamal,

On Wed, Mar 19, 2025 at 05:05:08PM -0400, Jamal Hadi Salim wrote:
> On Wed, Mar 19, 2025 at 2:12=E2=80=AFPM Breno Leitao <leitao@debian.org> =
wrote:
> >
> > On Wed, Mar 19, 2025 at 09:05:07AM -0700, Paul E. McKenney wrote:
> >
> > > > I think we should redesign lockdep_unregister_key() to work on a se=
parately
> > > > allocated piece of memory,
> > > > then use kfree_rcu() in it.
> > > >
> > > > Ie not embed a "struct lock_class_key" in the struct Qdisc, but a p=
ointer to
> > > >
> > > > struct ... {
> > > >      struct lock_class_key;
> > > >      struct rcu_head  rcu;
> > > > }
> > >
> > > Works for me!
> >
> > I've tested a different approach, using synchronize_rcu_expedited()
> > instead of synchronize_rcu(), given how critical this function is
> > called, and the command performance improves dramatically.
> >
> > This approach has some IPI penalties, but, it might be quicker to revie=
w
> > and get merged, mitigating the network issue.
> >
> > Does it sound a bad approach?
> >
> > Date:   Wed Mar 19 10:23:56 2025 -0700
> >
> >     lockdep: Speed up lockdep_unregister_key() with expedited RCU synch=
ronization
> >
> >     lockdep_unregister_key() is called from critical code paths, includ=
ing
> >     sections where rtnl_lock() is held. When replacing a qdisc in a net=
work
> >     device, network egress traffic is disabled while __qdisc_destroy() =
is
> >     called for every queue. This function calls lockdep_unregister_key(=
),
> >     which was blocked waiting for synchronize_rcu() to complete.
> >
> >     For example, a simple tc command to replace a qdisc could take 13
> >     seconds:
> >
> >       # time /usr/sbin/tc qdisc replace dev eth0 root handle 0x1234: mq
> >         real    0m13.195s
> >         user    0m0.001s
> >         sys     0m2.746s
> >
>=20
> Could you please add the "after your change"  output as well?

Sure. I will send the official patch tomorrow, and I will update it with
the information as well.

Thanks
--breno

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250320-demonic-marmoset-of-economy-bba7ed%40leitao.
