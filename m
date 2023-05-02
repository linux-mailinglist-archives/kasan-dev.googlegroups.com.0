Return-Path: <kasan-dev+bncBCQL3ANPQICBB2HHYGRAMGQEYTMSQYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id D57656F3C20
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 04:22:33 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-3ece8a3e6e8sf18422921cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 19:22:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682994152; cv=pass;
        d=google.com; s=arc-20160816;
        b=wlTVoK6eh76pcKih5qb2GND4uSGEsNr5bP89/zwc8FmrlcZwaSA40+hphK3cf4AYxm
         EIGWMdY05b/HkoAv3QFYubrXQ2qr4gUx3EeYQZJvVFpYPsxG+pBYlmBVQIXT1zayJkgH
         k6ik1NpGPGu8OJjs0GlFa4hI6KfxiTZtZSnT1iVs0+MSDboYB7aBGA5Ql9iWEE5XKP7R
         +DJL33QP2CsTdju0UDUA/0uslPUSc0qj3IHCf/Dn5wOWPFogjTDU8R5ZJwygWCqvKLME
         StGs9UOTrMG11YvQ21SkQy7SbqUcSMq7LtGzJTe1P5BP7ldaN0PZ9tTBZaH7gbU/KrhP
         2hmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:date:to:from:subject
         :message-id:sender:dkim-signature;
        bh=eWAJ0Kb+TlLii90C/UUW5c5iMpxFB70k8oaSaoPWrPQ=;
        b=idBix2Fe1AbSqnMiBMSY3KPAXr50sBLgyPG9UhkvDr/V5tiNeUulPtuAJNIeH7Mws4
         4Lb0dh04mu/Gk8n4aYkJWNH6b4hKLUHyOhOxqlyv2vm/QhxqOyx75oh0a75qtG1ojlJ7
         FoKr2FsLn8vALumC7gt3ube3ZIp1SeTG1P1OVUf2biy87G8lKMvHzXHiY8FoxrMWhBFE
         vdBv1gRHFU+QoEvUJIe/KS8mDWZaH03h/HCLRL7eNAHpTpyk/Dz/LYziH6St/hrE/UYj
         US0TThe8waR2qgL5dGjm4lCdvDKXWwaWxFw79TSfYEXHbfiG+TLGX0FCQdj8VYUJFPXL
         KlJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@hansenpartnership.com header.s=20151216 header.b=B3+pvvNt;
       dkim=pass header.i=@hansenpartnership.com header.s=20151216 header.b=m6bYz5hN;
       spf=pass (google.com: domain of james.bottomley@hansenpartnership.com designates 96.44.175.130 as permitted sender) smtp.mailfrom=James.Bottomley@hansenpartnership.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hansenpartnership.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682994152; x=1685586152;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:user-agent
         :references:in-reply-to:date:to:from:subject:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=eWAJ0Kb+TlLii90C/UUW5c5iMpxFB70k8oaSaoPWrPQ=;
        b=ZsWAbxi+jauGBq1U4+8BnGHz0BmVYULX/ASMxFAgDgncnqrNX3C16Osfc2ikqM4pti
         i8Fgbi5rjhFGTkY4gZ35TBmJA457xqkofMrgj+ERf8udwof4ob67cAo9ONPLAkS8hlRH
         NWaI+9o0XMOWC5tb5R6A+Jy8dJcjnWUkrJfSOd5vlocE7uBF+yLO8N1/0gzEFnkoqbLb
         sUny0Y3PqUh5xy4uw8f1+22DWxdVFkWUVPTXMcU6o4tPFGz0UXO/0rAvAS/Br3i1wdDV
         nhInf4vxw3k+A6TUzrsW3xvGwZZGvofA+iWGcA3Xt1dtbCtBqWakK+PAYj3DesXho1SJ
         HjKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682994152; x=1685586152;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:to:from:subject:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eWAJ0Kb+TlLii90C/UUW5c5iMpxFB70k8oaSaoPWrPQ=;
        b=f0r1UYdBBz+mLnl5lnPWNJmOJqot95WWfZalSEooxK4rsbiTmDc1lHoqeKG5e0ELW7
         qtEZx5DHUcqwq8Pt6OGkQT6W43iZ++cY0ZTU5jXs60F5FrJsqDj3ot0RYKubzc39L30c
         HTxhBN6B3PyV1AynNe+pwmyP2V++CcOuysrdGyPUrVjxE8c7kPgec3PEDxvxcJSl70kf
         KQJeEdAFJ6vEBYA7XPGWIhg5HgPI9D/kryrprlJGnW/fqD5bnIQ6OZcoxvWggOlek8QV
         FKe2/49ruE1LWaNyOsXbN9Mr6kbGwW1h5wmXVzGS3RGOh/lYHZUe/Vu5XbesLs2TYtEq
         O9aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxUHyKiRkLUV7edqtZRfp22h1lwVhVdJpDYlYVuCazbizkf7c1S
	IqUDSzrkQHpPhT18GptW/3w=
X-Google-Smtp-Source: ACHHUZ70jZ7LCAYlziHPQdiruBiMb8JObVx7lj9L4a2DQuK7+vT3jSCQw2HdF9EhKbUE3aAKcOImGg==
X-Received: by 2002:a05:622a:46:b0:3ef:33d0:88f4 with SMTP id y6-20020a05622a004600b003ef33d088f4mr5734905qtw.7.1682994152596;
        Mon, 01 May 2023 19:22:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:a1b:b0:3ef:4181:88b4 with SMTP id
 bv27-20020a05622a0a1b00b003ef418188b4ls11467401qtb.5.-pod-prod-gmail; Mon, 01
 May 2023 19:22:32 -0700 (PDT)
X-Received: by 2002:ac8:5f87:0:b0:3e6:98a5:a965 with SMTP id j7-20020ac85f87000000b003e698a5a965mr22797099qta.22.1682994152051;
        Mon, 01 May 2023 19:22:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682994152; cv=none;
        d=google.com; s=arc-20160816;
        b=1AJ/lzQovx8eQGybMBtaMB4MGkIRYdqmzZ4U9HJoacivV87g3v4kkDFfRzUnXj7cNC
         3GjzuSm3033zT70RhKpemU+9H5pTn/oLLOd13nJV+W+fh/VxqygIE6YSdxu7vNtJ4EZm
         Kks/Jz9gK10nS7Co7oNiIxdoWRDpamG1JxR2SwSUp7CnPUGoeqbbH+nwL5fmK5Pmfq1k
         T01j9gHP16c4XAxK2cc27fAJLUiRCpR1jJWr/rA+gvsKC8Og8TnTsS/jJvpi1bdLfW0b
         gPgdscPOm8bJEojUsmS7fygTg+MA+hjG035r1ZYVypW++O/h0SabmIQRILSAi5be0xcD
         3Yfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:to:from:subject:message-id:dkim-signature
         :dkim-signature;
        bh=C++Df9BzmVNRln88ucosybjZp4eYiwH1g94BsLwFQ1k=;
        b=BlyRZtHArBfl5ZkOPD/QdMce2a384DgFMlXA4zk7DBfXk+HX06s3E3l5gLXBG3qguq
         V9oDMNvjeFEB4kkIOGpncxc1wbFOs5B/zYr5W/EIIjk6NgIdWRkyKXR4iE9QmQEqwP7G
         Cbz+emk8MWv8ehGQZ+LoCxQuJKUxvqimMCNvTrS1NfycaofSHTGTmyrrH6WS79dTnJ1X
         8ZVbHqyxUGLw4em6AgxtdsHiECinVJkKFmr5VMqt/1MYxqXb5P6FM4hV5U2NqoxTCFt8
         NdpqzCP9WIzWLTDqS6RD1VPmSWygfz5eWpMkrqfgZ1GRC1ByfXZT5T6ONKG3WdURU2fu
         y1BQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@hansenpartnership.com header.s=20151216 header.b=B3+pvvNt;
       dkim=pass header.i=@hansenpartnership.com header.s=20151216 header.b=m6bYz5hN;
       spf=pass (google.com: domain of james.bottomley@hansenpartnership.com designates 96.44.175.130 as permitted sender) smtp.mailfrom=James.Bottomley@hansenpartnership.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hansenpartnership.com
Received: from bedivere.hansenpartnership.com (bedivere.hansenpartnership.com. [96.44.175.130])
        by gmr-mx.google.com with ESMTPS id dp14-20020a05620a2b4e00b0074e088d88e7si1631324qkb.1.2023.05.01.19.22.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 May 2023 19:22:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of james.bottomley@hansenpartnership.com designates 96.44.175.130 as permitted sender) client-ip=96.44.175.130;
Received: from localhost (localhost [127.0.0.1])
	by bedivere.hansenpartnership.com (Postfix) with ESMTP id 4F7921285D3B;
	Mon,  1 May 2023 22:22:27 -0400 (EDT)
Received: from bedivere.hansenpartnership.com ([127.0.0.1])
 by localhost (bedivere.hansenpartnership.com [127.0.0.1]) (amavis, port 10024)
 with ESMTP id F_0yxm5OGuTj; Mon,  1 May 2023 22:22:27 -0400 (EDT)
Received: from lingrow.int.hansenpartnership.com (unknown [IPv6:2601:5c4:4302:c21::c14])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (prime256v1) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(Client did not present a certificate)
	by bedivere.hansenpartnership.com (Postfix) with ESMTPSA id 25B2E1285C64;
	Mon,  1 May 2023 22:22:21 -0400 (EDT)
Message-ID: <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in
 string_get_size's output
From: James Bottomley <James.Bottomley@HansenPartnership.com>
To: Kent Overstreet <kent.overstreet@linux.dev>, Suren Baghdasaryan
 <surenb@google.com>, akpm@linux-foundation.org, mhocko@suse.com,
 vbabka@suse.cz,  hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, willy@infradead.org,  liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
 juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com,  axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org,  dennis@kernel.org, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org,  paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com,  yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
 keescook@chromium.org, ndesaulniers@google.com, gregkh@linuxfoundation.org,
  ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com,  dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com,  jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com,  kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org,  linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
 cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>, Michael
 Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt
 <benh@kernel.crashing.org>,  Paul Mackerras <paulus@samba.org>, "Michael S.
 Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>,  Noralf
 =?ISO-8859-1?Q?Tr=EF=BF=BDnnes?= <noralf@tronnes.org>
Date: Mon, 01 May 2023 22:22:18 -0400
In-Reply-To: <ZFAUj+Q+hP7cWs4w@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
	 <20230501165450.15352-2-surenb@google.com>
	 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
	 <ZFAUj+Q+hP7cWs4w@moria.home.lan>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.42.4
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: james.bottomley@hansenpartnership.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@hansenpartnership.com header.s=20151216 header.b=B3+pvvNt;
       dkim=pass header.i=@hansenpartnership.com header.s=20151216
 header.b=m6bYz5hN;       spf=pass (google.com: domain of james.bottomley@hansenpartnership.com
 designates 96.44.175.130 as permitted sender) smtp.mailfrom=James.Bottomley@hansenpartnership.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hansenpartnership.com
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

On Mon, 2023-05-01 at 15:35 -0400, Kent Overstreet wrote:
> On Mon, May 01, 2023 at 11:13:15AM -0700, Davidlohr Bueso wrote:
> > On Mon, 01 May 2023, Suren Baghdasaryan wrote:
> >=20
> > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > >=20
> > > Previously, string_get_size() outputted a space between the
> > > number and the units, i.e.
> > > =C2=A09.88 MiB
> > >=20
> > > This changes it to
> > > =C2=A09.88MiB
> > >=20
> > > which allows it to be parsed correctly by the 'sort -h' command.
> >=20
> > Wouldn't this break users that already parse it the current way?
>=20
> It's not impossible - but it's not used in very many places and we
> wouldn't be printing in human-readable units if it was meant to be
> parsed - it's mainly used for debug output currently.

It is not used just for debug.  It's used all over the kernel for
printing out device sizes.  The output mostly goes to the kernel print
buffer, so it's anyone's guess as to what, if any, tools are parsing
it, but the concern about breaking log parsers seems to be a valid one.

> If someone raises a specific objection we'll do something different,
> otherwise I think standardizing on what userspace tooling already
> parses is a good idea.

If you want to omit the space, why not simply add your own variant?  A
string_get_size_nospace() which would use most of the body of this one
as a helper function but give its own snprintf format string at the
end.  It's only a couple of lines longer as a patch and has the bonus
that it definitely wouldn't break anything by altering an existing
output.

James

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel%40HansenPartnershi=
p.com.
