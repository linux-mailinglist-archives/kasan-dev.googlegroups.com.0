Return-Path: <kasan-dev+bncBCS2NBWRUIFBBWOYYCRAMGQEBRZIBZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 986FC6F3999
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 23:17:14 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id a640c23a62f3a-94a355cf318sf369419766b.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 14:17:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682975834; cv=pass;
        d=google.com; s=arc-20160816;
        b=vOUWDEpn4Pud9lZ1ztIhQld7MijmMKzfj2gY7mW84/9FwtT+jhN3jLwxMqgRDb08U7
         pD+AsVtURco5+By7dHTXav3w/dzHbMOEZG58mm031/4fT5jzytMYRFKs4lFSqfs2XfeZ
         WanK1zqSWtsSfTmOipIWyaFd2ZHM1n4U7LVh52cQccgdJNo6sYUGbR+1648c8aG+7uVG
         webbD4XWd4veysffhAiUnIDR9H0vABofmFkc/cUiw147QYS/q/PfXXYBhx2y9nedTJzZ
         EDCIM6HeyLektYgCWuh+oYVYC6b3thEbXT3qkIiYuUZBeSRddicDugMfmG5gywxYORRo
         hKBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Y/DRiRYmpQcg/2e0it+2EqLx5eEtq9oBLXG737ILCcE=;
        b=UjlT7x1ZUqtETu0D+7E3C36kZTuLQcLtxAkUoqjxIB2GMuhITplJavWqS4FVTBTjr2
         TQqi8vmATFyaFZVnDtZ7HvCac+mUjse1cmx5HaC3+NzzsTIXoXfuhYR538hXv6+pvMkR
         Zcl57cPh2QBWzlrF3anDQJfDGd++3PABTmEOHyXKSDS/ZsLh/KybdRiKUttpTSTE2N+U
         7ApPFzZwQgYa0Zrc9bYvU3cnz8iPb6mfKFqBZrklQrBtNafMD9UrOnbWr2OePf9amLf9
         mRzckvv4di0fa/lRzkuIzR1Ylt91SG2bH/PNGaQQpbyAVjnln5xYgaKW3F9Rxx0oK+Sf
         Br5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lW6pMkkI;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::2b as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682975834; x=1685567834;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y/DRiRYmpQcg/2e0it+2EqLx5eEtq9oBLXG737ILCcE=;
        b=oPrmbHxTwH3IZ7jvgZ2M6qzmP22cFl8H94KA8Iy0JqzRVWcFMhkpa5PWEZe1ycyFFj
         fD6xkQKN9Bk5abnJizLaNW2Ek3nTvkCNlRJnsmTPNoTqHqjz8qA/NldQqig12BN8RD4m
         u3g8MFH7OsPNAEYv+Bl+7uqTWzqwCnn2vIPs2zln6Vs0JYyKBW9a0i6cwGZ0cU1zUhVF
         SjobjHzvSNFuioBMTIpFFfFN97RfAWleHZp15otmw8KQOpTr1YjyfiDyipiFHM/ZAAKF
         ZWcpatCbPGyRmMnXU/bT1YmzBHVJOtl40OEpWUMShXIGvGcrQjZ/2EgXm0+6fiTioXOn
         AOBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682975834; x=1685567834;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Y/DRiRYmpQcg/2e0it+2EqLx5eEtq9oBLXG737ILCcE=;
        b=kJ2cpo85vXvwPud7dS9EWZdRyiwd1O0rvS5THmWKERwbF7qNUh8S+LPD2et6wG7kTa
         Dr13mPG3Rjq4mJUyf8fe6zFkckhkBOmWkkV7ITXA/VLKAL7C9s5WtvFqzYAK8YMCNtkh
         AS3d+oCTcoUb0W2NAQBNGgB1f+YpWVZBqrvzPJk00gHkM2/5YMnEuGk9jhZ9vR2iVKe7
         r9DnczuqfUNKTBV53kE6Wx6es4ujzeBT9ZD/UeHsL83hdhV/tDe78yql+SKYngPm7bqT
         af8Qot9OwXLGGWyyQLq5eK6GsjxzbX2tWEsUiSsJXQff8tytpHI7beepunt74WwMXVDt
         /U4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxe0WaPrzndEuomjKF09EF2KBhKgpqMwx6xbLp8oBgnXzeHONQ2
	lFZKeiDr0ltuHwr/ngm3ksk=
X-Google-Smtp-Source: ACHHUZ6Xwnrh9s6yEBGzQTJHkGW4fD/XjSkhs/nbHAAXpGHJJDcWwz+LMjwUlEBrexEY7JsUzVQaIw==
X-Received: by 2002:a17:906:5a4e:b0:92f:fc27:8ea0 with SMTP id my14-20020a1709065a4e00b0092ffc278ea0mr4702466ejc.9.1682975833959;
        Mon, 01 May 2023 14:17:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:86a3:b0:94e:cd76:edae with SMTP id
 qa35-20020a17090786a300b0094ecd76edaels2636463ejc.1.-pod-prod-gmail; Mon, 01
 May 2023 14:17:12 -0700 (PDT)
X-Received: by 2002:a17:907:5c9:b0:94a:7da2:d339 with SMTP id wg9-20020a17090705c900b0094a7da2d339mr13903370ejb.26.1682975832742;
        Mon, 01 May 2023 14:17:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682975832; cv=none;
        d=google.com; s=arc-20160816;
        b=pG40MQ4OZQ5jik3EbCKJ1L7gt1NR55a0CBd6WSOEsD/7VFp46bgdvW8HuI1PFqOJXO
         fMUHNnnCI55r9s/jqHFE8oQpLIrE+27CetqsIzfDd3v9kaN9D6HeA+9J3puNz//Z9G+Y
         VP4H+rrvU1oHP7yvlv/vLZOZwn7JaHVu88Djg/ycPy+zfLdxKvjRo06V3er1VLVUAvUz
         9prGcwobrN22/reeD3xxeFLn6OyJbrDrFPo8/utT/BWVcUJenjww4aA26HaHCoM8iowi
         tfxMZ6FhjEzGIbp5hhRGTHI5O1sbIpNIqjybwgVUfwNS4hEntxQY6+Nwoon8cqp0ZIFr
         Nyig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=WS5IfKwTPa1bKv8dROPMPn7bpsB6bxr/+mMUnulbyXo=;
        b=LzPXJk3m9lnt6KsMeUtesL2cWb07GGxPu2rUF1pDBFyXfix0UuXYPr5naNiO4GtcLa
         3bpwDRBRT21UxauXix0hHOebZb1+X1v/PgF6VdQCAYbdkaMUW7UmHZqpNdkqbwDK4kPU
         63aQwRAb34E5XV2UBYK/lPPaWjr20tWg/pS2jwh6/Hu2C8LDHVsUbyR6vtwtUBqICe7F
         /n0D/rcNw76U5KAhHMqAZgibGMhiItd1yejT+6RdIdAzdkkvPzrXo0BLJLsx1trnUnTZ
         4EdLqjglnHxpAG5OxLubKTOmcy74gEFB622HZ6P4GJJJO12DutFfWtp9DEf169HtoBwW
         UYUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lW6pMkkI;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::2b as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-43.mta0.migadu.com (out-43.mta0.migadu.com. [2001:41d0:1004:224b::2b])
        by gmr-mx.google.com with ESMTPS id n11-20020a170906378b00b009531f349d24si2052058ejc.0.2023.05.01.14.17.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 May 2023 14:17:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::2b as permitted sender) client-ip=2001:41d0:1004:224b::2b;
Date: Mon, 1 May 2023 17:16:59 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Andy Shevchenko <andy.shevchenko@gmail.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Noralf =?utf-8?B?VHLDr8K/wr1ubmVz?= <noralf@tronnes.org>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in
 string_get_size's output
Message-ID: <ZFAsS5f6eGSyxF/+@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan>
 <CAHp75VeJ_a6j3uweLN5-woSQUtN5u36c2gkoiXhnJa1HXJdoyQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAHp75VeJ_a6j3uweLN5-woSQUtN5u36c2gkoiXhnJa1HXJdoyQ@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=lW6pMkkI;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::2b as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Mon, May 01, 2023 at 10:57:07PM +0300, Andy Shevchenko wrote:
> On Mon, May 1, 2023 at 10:36=E2=80=AFPM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Mon, May 01, 2023 at 11:13:15AM -0700, Davidlohr Bueso wrote:
> > > On Mon, 01 May 2023, Suren Baghdasaryan wrote:
> > >
> > > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > > >
> > > > Previously, string_get_size() outputted a space between the number =
and
> > > > the units, i.e.
> > > >  9.88 MiB
> > > >
> > > > This changes it to
> > > >  9.88MiB
> > > >
> > > > which allows it to be parsed correctly by the 'sort -h' command.
>=20
> But why do we need that? What's the use case?

As was in the commit message: to produce output that sort -h knows how
to parse.

> > > Wouldn't this break users that already parse it the current way?
> >
> > It's not impossible - but it's not used in very many places and we
> > wouldn't be printing in human-readable units if it was meant to be
> > parsed - it's mainly used for debug output currently.
> >
> > If someone raises a specific objection we'll do something different,
> > otherwise I think standardizing on what userspace tooling already parse=
s
> > is a good idea.
>=20
> Yes, I NAK this on the basis of
> https://english.stackexchange.com/a/2911/153144

Not sure I find a style guide on stackexchange more compelling than
interop with a tool everyone already has installed :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFAsS5f6eGSyxF/%2B%40moria.home.lan.
