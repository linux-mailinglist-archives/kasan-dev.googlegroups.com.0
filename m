Return-Path: <kasan-dev+bncBCLI747UVAFRBDFKQONAMGQEHNRGVBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A303E5F81FD
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 03:40:29 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id a9-20020a056e0208a900b002f6b21181f5sf5048952ilt.10
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 18:40:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665193228; cv=pass;
        d=google.com; s=arc-20160816;
        b=QvMIia7qBgINHuzws2WeMYbNA9q+bSu24T9Yc4+X22eswnLgqVK7SmRJ/Vn9DMxbcW
         n4j8BcK/w7ZemT+syc0ag8ONBlmafVArvOwhm9cKsdMAMUdil6weAFaFKdFFSfXxUaMY
         rMliESVtxpuqIQ/2dVD+q/zW64uFi2EHD3zYShwyntrVw9Hwz1UZp9lHA5e+YKCZBqjy
         pJt0tMenDppde7Ywiiw1msRMqXTbcNv4htTB090iAUeyMY3Cdso1fatvamXoeLC3YeCJ
         LUEmMvY0RI1e2ieDU1ylosQqTNnuXeNT0/YnU1UOJ+uO5nxG8snVd3NGUZQly7UlvE7D
         OgLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=TNkfTMAHvHUHFTw4bE2P4uYSd5qKagg4rWmIKWypZns=;
        b=xMT5cAgeV4Q1luCzF/lLb15c0SJLM5OGkLOfPu5te9qVdJu+r1Sm47mr3O1EJpFu7S
         jM8pNuIEEpH2PDsF4NEyx24X9KnuDFCYNNzV4FL9s/sxCpznaAIFU2oAl13yWY6WEK+F
         vIv+vRXIqYGQmMPxerctqskUugrHtw708/geCrUvOabnNWWrz0Fbz3hL18jSX3Xiy4k9
         r9K5/dMRLjs2IKZtswDacyn7US0C9qYxwUnlLmvzvOqVsuwf4Zgs72eRHX8zx/YIRmNA
         2qWOAozyom9nDbiic8unxcrA1GgANweqwnqOX6nUA02Wc66iICg0r8+AvlWbyvFyy1qY
         eg6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=m7dkF4Qq;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=TNkfTMAHvHUHFTw4bE2P4uYSd5qKagg4rWmIKWypZns=;
        b=A+5CkRFFPZ52mXkK5ZZm4zZq3Yte/TNtcKt3f1e/uWkgQKa5U2PZY98EGltET/YhTt
         O+FEdNdI3EAL54ZYYA9HecCwnyV8xBrMBCsZ+QVGxl8VGfIDQZ3nu7OBR/gUZKyl4v+W
         1KanRIwpGAKOGpvN+qPn3ZngK3TjF8F6fuYBqZHtPBVeV8wdhb4XcylBPKqTPPYaB6Ol
         3GWJAm9ORccwUfQ8W3B62znCNc8VsEHpjldG2JHSZvXC6CUbG86RVzJ9uXoudhE8pN8+
         OuM247mVxVqNgVip3o6FYnV5b4bpwSawlOWR5QJQ12It10mktGvuWM/aQ3Na1sbCVQ2K
         LNzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TNkfTMAHvHUHFTw4bE2P4uYSd5qKagg4rWmIKWypZns=;
        b=7Au6k/xftyRsLnGorZ27KYKSJ1F5qxEzBZANI5MqsE/CS9djR+Kmx8JTaGi2L+4oKX
         3XwHZJnaeBtlPK5YeCvMZ/Gsqaca+h3R2OcGRmUpR5GDdZnCEE9CYlW2ySlqNasQIt0u
         oCcPbNgB0MBe8kZbQ7fgI5Ldh3gs9eINFnGPNugk9R6RgrSKh3YufHJMSlRNn4CjJd4p
         09ns/uGMSjZv5NCIp5I4LlHaYft3VLCEVf6wEZ6ZC3D2jMUqnGOPJtyC9H/gdmwqeiyp
         RPm9P/7TL7RNyWl4EFAZ29Z5q3OEWoFwfG6jQLS2Cak0e8E7ht8bpYqmwqZhOBUHYWsy
         FyoA==
X-Gm-Message-State: ACrzQf29h7k5hcxfvjifgKjQzmSSAvO0dLKX8jmIhsRgZtNkl4TjsWmC
	ejVvH7DUZTBe4RHDoDkrC+E=
X-Google-Smtp-Source: AMsMyM6lNgAxpQwqdZODsB1C9QHiL5pY8Xd7dyB/ogzTgT9gSsPCiI5efCvAQ4Ka7vi72roO4F+3BA==
X-Received: by 2002:a05:6e02:1447:b0:2fa:27f2:fb44 with SMTP id p7-20020a056e02144700b002fa27f2fb44mr3677100ilo.128.1665193228222;
        Fri, 07 Oct 2022 18:40:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:d06:b0:2eb:1346:cc45 with SMTP id
 g6-20020a056e020d0600b002eb1346cc45ls1364541ilj.11.-pod-prod-gmail; Fri, 07
 Oct 2022 18:40:27 -0700 (PDT)
X-Received: by 2002:a92:c651:0:b0:2fa:e0fa:509 with SMTP id 17-20020a92c651000000b002fae0fa0509mr1671379ill.181.1665193227751;
        Fri, 07 Oct 2022 18:40:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665193227; cv=none;
        d=google.com; s=arc-20160816;
        b=cOx3WbqNr9m0QOnJHHbLZ4mujCdsFpgkbZ7/XDV+TrXy3l1rn8gd4ndUhSi5fdCW3u
         eIEW5kTzOVOAMW29LqXBESR3X3sd6quUBq3Bsdu9jRDd/MiNlgEw2LSetj0mM/n5VP5R
         CqSHqUNgZagG11rElbMY4kScdg2TtYKbnz5190Rka1vpp9X6MJVtdrvwsxT9VKoeSNBg
         nJt24tEYZHq7ULGjpfZlx6v6k8bhW/3vxLzEJZZvi0N+DojzacRgUyoR4xYuhcgD3gf5
         7AgPf5BVrmsPRXA2JCLhnLj6qe2wBP8umJ18gvBRJljTiJl8VFnNNbzq3R4t88+5mtls
         1BhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vNH2mnpIcj00WUdnQLlhiavniZvHilK6oGwgWIcL7uw=;
        b=p8X144lM9Lr8Eeyk+Xde0GKR+ZzZCP8IUKu0kiQxb4Bl7gCXS4O7pw0HaBO/hRe+94
         aekZH6yqFMvbSRmcYYcKVGWMevybkEoRMX0I5Wt/eYL3TS/IFJivqptLC5g7uNZYyVQS
         Kj6sACyPfhgdp5/xFkin5uQSK6lTPbW183nhYhjij7vXe8koZX4y8ntcad4XHTDZ383C
         74pRUvPEMsnFyyyh94/w0WcYGUHdGfXaTUxFTArnzLJpwIQnK5Pzdgfbv8O2HO9VkZlX
         epG+vrqBXFtG1l+SHX1C3t8qEtmMZswVtW5XfTNeh5/Dm2EQTGV+jQRrEYJv1kyTOXUO
         aaUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=m7dkF4Qq;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id n15-20020a056638120f00b0035a25c888bcsi150347jas.2.2022.10.07.18.40.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 18:40:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3B32061DF3;
	Sat,  8 Oct 2022 01:40:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1F81CC433D6;
	Sat,  8 Oct 2022 01:40:20 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id f0b17dc7 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sat, 8 Oct 2022 01:40:18 +0000 (UTC)
Date: Fri, 7 Oct 2022 19:40:07 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Rolf Eike Beer <eike-kernel@sf-tec.de>
Cc: linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	andreas.noever@gmail.com, akpm@linux-foundation.org,
	andriy.shevchenko@linux.intel.com, bp@alien8.de,
	catalin.marinas@arm.com, christoph.boehmwalder@linbit.com,
	hch@lst.de, christophe.leroy@csgroup.eu, daniel@iogearbox.net,
	airlied@redhat.com, dave.hansen@linux.intel.com,
	davem@davemloft.net, edumazet@google.com, fw@strlen.de,
	gregkh@linuxfoundation.org, hpa@zytor.com, hca@linux.ibm.com,
	deller@gmx.de, herbert@gondor.apana.org.au, chenhuacai@kernel.org,
	hughd@google.com, kuba@kernel.org, jejb@linux.ibm.com,
	jack@suse.com, jgg@ziepe.ca, axboe@kernel.dk,
	johannes@sipsolutions.net, corbet@lwn.net, kadlec@netfilter.org,
	kpsingh@kernel.org, keescook@chromium.org, elver@google.com,
	mchehab@kernel.org, mpe@ellerman.id.au, pablo@netfilter.org,
	pabeni@redhat.com, peterz@infradead.org, richard@nod.at,
	linux@armlinux.org.uk, tytso@mit.edu, tsbogend@alpha.franken.de,
	tglx@linutronix.de, tgraf@suug.ch, ulf.hansson@linaro.org,
	vigneshr@ti.com, kernel@xen0n.name, will@kernel.org,
	yury.norov@gmail.com, dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-media@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-mm@kvack.org,
	linux-mmc@vger.kernel.org, linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org, linux-parisc@vger.kernel.org,
	linux-rdma@vger.kernel.org, linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org, linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	loongarch@lists.linux.dev, netdev@vger.kernel.org,
	sparclinux@vger.kernel.org, x86@kernel.org, toke@toke.dk,
	chuck.lever@oracle.com, jack@suse.cz,
	mika.westerberg@linux.intel.com
Subject: Re: [PATCH v4 4/6] treewide: use get_random_u32() when possible
Message-ID: <Y0DU93wMsDwlLmMP@zx2c4.com>
References: <20221007180107.216067-1-Jason@zx2c4.com>
 <20221007180107.216067-5-Jason@zx2c4.com>
 <3216619.44csPzL39Z@daneel.sf-tec.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3216619.44csPzL39Z@daneel.sf-tec.de>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=m7dkF4Qq;       spf=pass
 (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Fri, Oct 07, 2022 at 10:34:47PM +0200, Rolf Eike Beer wrote:
> > diff --git a/arch/parisc/kernel/process.c b/arch/parisc/kernel/process.c
> > index 7c37e09c92da..18c4f0e3e906 100644
> > --- a/arch/parisc/kernel/process.c
> > +++ b/arch/parisc/kernel/process.c
> > @@ -288,7 +288,7 @@ __get_wchan(struct task_struct *p)
> > 
> >  static inline unsigned long brk_rnd(void)
> >  {
> > -	return (get_random_int() & BRK_RND_MASK) << PAGE_SHIFT;
> > +	return (get_random_u32() & BRK_RND_MASK) << PAGE_SHIFT;
> >  }
> 
> Can't this be
> 
>   prandom_u32_max(BRK_RND_MASK + 1) << PAGE_SHIFT
> 
> ? More similar code with other masks follows below.

I guess it can, because BRK_RND_MASK happens to have all its lower bits
set. But as a "_MASK" maybe this isn't a given, and I don't want to
change intended semantics in this patchset. It's also not more
efficient, because BRK_RND_MASK is actually an expression:

    #define BRK_RND_MASK        (is_32bit_task() ? 0x07ffUL : 0x3ffffUL)

So at compile-time, the compiler can't prove that it's <= U16_MAX, since
it isn't always the case, so it'll use get_random_u32() anyway.

[Side note: maybe that compile-time check should become a runtime check,
 but I'll need to do some benchmarking before changing that and
 introducing two added branches to every non-constant invocation, so for
 now it's a compile-time check. Fortunately the vast majority of uses
 are done on inputs the compiler can prove something about.]

> 
> > diff --git a/drivers/gpu/drm/i915/i915_gem_gtt.c
> > b/drivers/gpu/drm/i915/i915_gem_gtt.c index 329ff75b80b9..7bd1861ddbdf
> > 100644
> > --- a/drivers/gpu/drm/i915/i915_gem_gtt.c
> > +++ b/drivers/gpu/drm/i915/i915_gem_gtt.c
> > @@ -137,12 +137,12 @@ static u64 random_offset(u64 start, u64 end, u64 len,
> > u64 align) range = round_down(end - len, align) - round_up(start, align);
> >  	if (range) {
> >  		if (sizeof(unsigned long) == sizeof(u64)) {
> > -			addr = get_random_long();
> > +			addr = get_random_u64();
> >  		} else {
> > -			addr = get_random_int();
> > +			addr = get_random_u32();
> >  			if (range > U32_MAX) {
> >  				addr <<= 32;
> > -				addr |= get_random_int();
> > +				addr |= get_random_u32();
> >  			}
> >  		}
> >  		div64_u64_rem(addr, range, &addr);
> 
> How about 
> 
>  		if (sizeof(unsigned long) == sizeof(u64) || range > 
> U32_MAX)
> 			addr = get_random_u64();
>  		else
> 			addr = get_random_u32();
> 

Yes, maybe, probably, indeed... But I don't want to go wild and start
fixing all the weird algorithms everywhere. My goal is to only make
changes that are "obviously right". But maybe after this lands this is
something that you or I can submit to the i915 people as an
optimization.

> > diff --git a/drivers/infiniband/hw/cxgb4/cm.c
> > b/drivers/infiniband/hw/cxgb4/cm.c index 14392c942f49..499a425a3379 100644
> > --- a/drivers/infiniband/hw/cxgb4/cm.c
> > +++ b/drivers/infiniband/hw/cxgb4/cm.c
> > @@ -734,7 +734,7 @@ static int send_connect(struct c4iw_ep *ep)
> >  				   &ep->com.remote_addr;
> >  	int ret;
> >  	enum chip_type adapter_type = ep->com.dev->rdev.lldi.adapter_type;
> > -	u32 isn = (prandom_u32() & ~7UL) - 1;
> > +	u32 isn = (get_random_u32() & ~7UL) - 1;
> >  	struct net_device *netdev;
> >  	u64 params;
> > 
> > @@ -2469,7 +2469,7 @@ static int accept_cr(struct c4iw_ep *ep, struct
> > sk_buff *skb, }
> > 
> >  	if (!is_t4(adapter_type)) {
> > -		u32 isn = (prandom_u32() & ~7UL) - 1;
> > +		u32 isn = (get_random_u32() & ~7UL) - 1;
> 
> u32 isn = get_random_u32() | 0x7;

Again, maybe so, but same rationale as above.

> >  static void ns_do_bit_flips(struct nandsim *ns, int num)
> >  {
> > -	if (bitflips && prandom_u32() < (1 << 22)) {
> > +	if (bitflips && get_random_u32() < (1 << 22)) {
> 
> Doing "get_random_u16() < (1 << 6)" should have the same probability with only 
> 2 bytes of random, no?

That's very clever. (1<<22)/(1<<32) == (1<<6)/(1<<16). But also, same
rationale as above for not doing that.

Anyway, I realize this is probably disappointing to read. But also, we
can come back to those optimization cases later pretty easily.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0DU93wMsDwlLmMP%40zx2c4.com.
