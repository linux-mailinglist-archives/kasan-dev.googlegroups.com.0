Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBN2XKLAMGQEN53UVRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 33A28573409
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jul 2022 12:23:03 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id z1-20020a195041000000b00489cc321e11sf4877248lfj.23
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jul 2022 03:23:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657707782; cv=pass;
        d=google.com; s=arc-20160816;
        b=DVbBGI5ckm9G5XseAAxpMd73kbNaYVgi//C9gRxA7XXkZpkd96oojOhgEqSq96x7ps
         Beg1Ibn+R+qsdFUf5WC35a5jioqzDm8+X6n490ouyQpnkJwHEKAU7vnjQTmk0swtGz5g
         yVwktnA9xYU08EF0uN3T2fnhJiyxgs0jM+nhFju8clnFRb3F69kSutyOPfZQVSKHHCts
         tXgBHM4jTN734Jf9D3ijZXrnZoyjg4oedWNWHBH12yn8w5iu66XA7y+aBwluMDlklbgw
         9GltPe/MX2aBFT3EeDs4Bm3VPnELByVhpsGjtrjzDEoA/9NRvnvMel2x9ngEmX7gPDna
         iuMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=z6VgdQ16dMGbopYkn7d/px3RNd9GdqX2w0B07QiAtSQ=;
        b=lAg7pjeDMPyhgX0xSffENFx4ee9de00XZLiCiW4Q3EMdYW/wxd52USPGwrKQvajusJ
         4MscLW3kayOdm8ZbHKVGSNG0ljRvo0VVGTL57sh1NS9bihK5rRWyGQAjaiNH5srPIFnV
         5Ifzg2VkoK6+9y2/BFCAZdy0xt2ZA1znMc1xhegQhirTBPp5dVbmvoAxsWInq5fdRBH/
         1pEWw9NKeoHNikcu8VyyjIxPedUG3PQub/vBK4DsnuZ1M/9riZE202+bs69P/Y8KajJb
         57EjeL6zl+ROvNkfZxkIJsAdgvaFjcvKRRwG1+o6rZ+/XRcNa1fvzyAjW8P2/5Ryf5y5
         6utA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q5OYPMJH;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=z6VgdQ16dMGbopYkn7d/px3RNd9GdqX2w0B07QiAtSQ=;
        b=Kitbzf1z7fiFLBo/JNPWmjF3Nl6mHzXDR1m3zL6ljqrVui+pOvCvPhhL4RFqrCMiye
         cE7eTEPx4YI6sdG3c3Uvy7mWI/BkyxthT5LsVaAbDc6gSg0fW/g5gcPfF/8U1RRDwhVF
         bhVq4zPG45Y+y6qCoeTnndr88Bkuh1E2KOPTnkxb+AImvPv3lAGXeNnYpZkIzusxaAv0
         GXe59wpxskcdN5vVmWxJ02UTHJtLVUGNzDeBkA4i+LmhvSFtnR25TwMb2+maiJ/b617p
         0vWxz2jW7ZzOvpOAjvKKyHzpuK+KuGoU5lbfmzyLaz1e5rWK1IFeFI37JgUOcNGKufFY
         vbVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z6VgdQ16dMGbopYkn7d/px3RNd9GdqX2w0B07QiAtSQ=;
        b=t4P0N3KTCzUfiR0wHm2lmTn9tKd/o1Wydg3TIFPcJQPfpeN6oM0CobG8x88QR+acaE
         co0ixVOcH2aKxEsFLHCk4up/l9Sv2kV4gzREAVFc4N0x/GnWvE1dnoBWCmlUlfAp+mSG
         wse9gI9rpAZifCOmyHPFU3bvx/IiplRd8bQMTvjLFzTop4qVlmUNI1sElk7FwuEjFF9p
         8IW/30iz0aBHmJdyPrtLmwihHirZavfnfzNng+IsfCkd3mKI0BfRdMkFmOLuxkx/5FbD
         U0R1q/v1P+5z9hHzcOG9lch2ckHeab4aUnOy/O8FhEtt1Jkzg5s3EJk5sAOoghlfKmbJ
         9XXA==
X-Gm-Message-State: AJIora+b/4nLoD1ImuvCni/PMf7615+wtLqc4iYfgnIh2fcP4GAVGJLZ
	HmJwfvK5Hd3LXNYqonAsJ/g=
X-Google-Smtp-Source: AGRyM1s6H4TN7/zW2bXb/V7W/bwGiG+6PQm3rdSetbUS8N/UYasIH12dZjsdJTXx86Nopr39s16/pw==
X-Received: by 2002:a05:6512:4004:b0:481:2c04:2bb3 with SMTP id br4-20020a056512400400b004812c042bb3mr1513439lfb.680.1657707782401;
        Wed, 13 Jul 2022 03:23:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b9a:0:b0:25d:8520:aeb with SMTP id z26-20020a2e9b9a000000b0025d85200aebls405915lji.8.gmail;
 Wed, 13 Jul 2022 03:23:00 -0700 (PDT)
X-Received: by 2002:a2e:9bd6:0:b0:25d:8712:64f6 with SMTP id w22-20020a2e9bd6000000b0025d871264f6mr1311778ljj.337.1657707780724;
        Wed, 13 Jul 2022 03:23:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657707780; cv=none;
        d=google.com; s=arc-20160816;
        b=tsVuDE3uasXKoOAjt7Z1I4YRT8GGbhKMW4czYEnUL0mXqvvwe5qr0QH29FbEJfbn2a
         3Z+bP7+Ge3itrM7OpZhUUJmPu7fcbB2xAZFKpsqf99WG2+T0VWw231Sp0tRMC8tmQp1B
         MgheDRkxpnuJb7CMHSQvRIFGzi9yz/WVFhXrG77F+OvqfsHPN+dsrNKdfh2ZXWK7vkhX
         QGvkLMmrzVZQtPgUI/1k4FhgqFXq9AE+7C6E7UswFJIlDpU0EkhNSKudBq8Yq90nJTcP
         x01xxz8m9vNhQUz1PNUdSv8cxt/xOeaJEnixcGFMuEFYZ8nzAm2doDhU5E0CnPZ8v8ro
         +s9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=p3iDfE6X71ht0fb+AD37KbLhdKay+NMX0GxKDHXhdRo=;
        b=gxzmvMTCKs1JF009T4a22G3UXs7ccyBAvk+Uyio/+05w9f4wYp1NzrakzBZ1s03VVe
         iXm8gOVHkt5/InHYE/jMTIg1iRIqMkEnD1V5twSEvN2iQ28RpSd4Sspb7HGAzV0nwzUR
         it7q0rx2Ba3dvTrbMk0AkhTn7FW43vs598EsD72+msSeycODhSN8HVJQ0oxTuh2bwV6c
         lNZvFdh3ZlJzK22HDIVf7F6lGk3xUOYX/8wntkd1snL3mmzLQ5bGUy5N90XMtwDM7lUX
         JEbvf7fHquYRGJUK0fuxFMpiNkqQwnU4E5Weo54a60nUDQBOf9FuFtzPSenFYIJXY4mF
         F1Kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q5OYPMJH;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id k16-20020a05651c10b000b0025a70508721si491023ljn.7.2022.07.13.03.23.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jul 2022 03:23:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id h17so14883314wrx.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Jul 2022 03:23:00 -0700 (PDT)
X-Received: by 2002:adf:f1d1:0:b0:21d:7f88:d638 with SMTP id z17-20020adff1d1000000b0021d7f88d638mr2542788wro.586.1657707780036;
        Wed, 13 Jul 2022 03:23:00 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:63e6:a6c0:5e2a:ac17])
        by smtp.gmail.com with ESMTPSA id g6-20020a5d64e6000000b0021d887f9468sm10685642wri.25.2022.07.13.03.22.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Jul 2022 03:22:58 -0700 (PDT)
Date: Wed, 13 Jul 2022 12:22:52 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthew Wilcox <willy@infradead.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org, Eric Biggers <ebiggers@google.com>
Subject: Re: [PATCH v4 29/45] block: kmsan: skip bio block merging logic for
 KMSAN
Message-ID: <Ys6c/JYJlQjIfZtH@elver.google.com>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-30-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220701142310.2188015-30-glider@google.com>
User-Agent: Mutt/2.2.3 (2022-04-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=q5OYPMJH;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, Jul 01, 2022 at 04:22PM +0200, 'Alexander Potapenko' via kasan-dev wrote:
[...]
> --- a/block/bio.c
> +++ b/block/bio.c
> @@ -867,6 +867,8 @@ static inline bool page_is_mergeable(const struct bio_vec *bv,
>  		return false;
>  
>  	*same_page = ((vec_end_addr & PAGE_MASK) == page_addr);
> +	if (!*same_page && IS_ENABLED(CONFIG_KMSAN))
> +		return false;
>  	if (*same_page)
>  		return true;

  	if (*same_page)
  		return true;
	else if (IS_ENABLED(CONFIG_KMSAN))
		return false;

>  	return (bv->bv_page + bv_end / PAGE_SIZE) == (page + off / PAGE_SIZE);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ys6c/JYJlQjIfZtH%40elver.google.com.
