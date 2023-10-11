Return-Path: <kasan-dev+bncBD7LZ45K3ECBB3MSTSUQMGQEHJOBZJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 46B147C5EA1
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Oct 2023 22:45:36 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5056b17f0b9sf1133828e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Oct 2023 13:45:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697057135; cv=pass;
        d=google.com; s=arc-20160816;
        b=heDgBS4BeTjDTEK5mOU3UapqpCEAB7Pz4bN1ecPa3aj3bkSfCOxujobHPbT3PjSeDJ
         7sLr/3bfCj7RwrAAfFEQxHXB9nEqU84yHBlDzRNOIFjRXzpxxd6TyMIqarvmBO9KsGAr
         yO/Mp0YvCS9smdU2b45RgTOL//wI6Fp6ljHN1SJbu5lXAcR7r57+GwStXAZiKkM3ZJT7
         AJyFNQbLXH5AKlXQHZnwOL/TUUU9ybTpvB1uDeNKFKy6FZjG+PfPYMKxIjRAPMIaLhEP
         DfNaZkTbsz2wZMxvewiNCPeIFgbnVuDG1rbsaUfj+l66QsQvBjj3tOCDOHmvoVL47+EV
         xOMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CzDhcGYHiLiEzTEWwRSz53ejCXviqvy2BRfqGfDBwJI=;
        fh=rJ8h3sxjJc+y8EYBgZD01cbd9o5icJkeDxe+3MZXRtM=;
        b=OsNtQL+KjRqmnwvSI+BkKbPdZPUo7JzPKIHCKEeeClbtJyGIFvHaAV3/EYctG1j248
         EfwUFQYl4Qy7lFRKxwdCdMiBHMRAwSyw1GVNGThngD0OCIl0olVwwOIfVHDsHiTU7XJW
         /LQPprSKmmVZMziFXIfix1Jjd+1FsdjU/4NBVZYO30UysNtQXllwkNt+H0tVCmegY4rj
         /VtO6rEpZ4NclUyOFme0wTEBQcQrzuqUW2CwvIC2q/Xfl9QwIL9RUGzlC2+uIHMGj31u
         8BiaWfbfrD8Wvf1Kx1a8cvQRKpc06ZAPXJXQh0ywMuzIYNBf3NWO80aar7wodFKznOwv
         ovNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=K5DwM+5u;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1697057135; x=1697661935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CzDhcGYHiLiEzTEWwRSz53ejCXviqvy2BRfqGfDBwJI=;
        b=LHXdiBxaPMWjd+bQqALv6d6ZZQA541t3lpe41b4DieR1vlMAs/VTy6ee6p4Iy6fYnu
         AzSaV/isFJPEpkf6GX3b49AmdUcW6n5ShgxzVpotrT3/yXrmKG1RtkDUrbSqkzTmIO/e
         2dgUSjw8WZgE0cZdEmuQE7yEidfmB8URPaIYrwuBYAYF8i5qzKQYvJqZMYiUzWsZmdyv
         hwGdEMvJdNaNqENEH/KEKN6Vr+A58/V2aC4P4fphYu2tybANg1lbbUASoz18xhrkNcYP
         GCcO4Gf1wYmRONS63gdGvM23BmJzLGoZ/CdOqJIGDT1RaQXN/lYoWEy2vS35KWgscmci
         5utQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697057135; x=1697661935;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CzDhcGYHiLiEzTEWwRSz53ejCXviqvy2BRfqGfDBwJI=;
        b=L8euJcPSTRViLf5bsgerf1FY3gTh6FqPYDlBHB+nDNPSjSMt+GuRSvsPQRGeUS4HlJ
         tB1aHFBz+VZXHaEk+yQ2p5t/xceoAE4etomSeVxf2WREQS0iLnEYaihu0HI+jEZuS0nc
         jYDGBI6fmFpysZPjzIztVV1ev4QeLAayUeKAgqTctXoecZYk0oSMP0lqnjvXt3nWW050
         wVSivGToVtOmfZd3kIywfUh8k47MH52gHF8nkjyOv6pwmFxKyRZZdMD0U0Nk15e1bvry
         2+wRrCjwKv3L+w5NDzKfZHxd/yDLRuPGBiMRrFkMv28BhIG2fVNU72L7pyHSYKOarSr1
         fAFA==
X-Gm-Message-State: AOJu0YwcS7+gXJYkENbIO+2QqIIUG5/zcgu9PxKsQ3fSWd3Vk1NFuxXo
	U60/38GHhAUx3RwGi6aR+Bk=
X-Google-Smtp-Source: AGHT+IF2/w7Ud3/w+QT1YM+G/UogSSPZjNYa+b9tqA72b3GiHOht5rtvDpYusJPGO4UPw4kkvfTv7Q==
X-Received: by 2002:a05:6512:3415:b0:501:bf37:262a with SMTP id i21-20020a056512341500b00501bf37262amr20549321lfr.32.1697057134087;
        Wed, 11 Oct 2023 13:45:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:8c0b:0:b0:505:667c:be15 with SMTP id o11-20020a198c0b000000b00505667cbe15ls105295lfd.1.-pod-prod-00-eu;
 Wed, 11 Oct 2023 13:45:31 -0700 (PDT)
X-Received: by 2002:a05:6512:2308:b0:4ff:839b:5355 with SMTP id o8-20020a056512230800b004ff839b5355mr15029132lfu.18.1697057131499;
        Wed, 11 Oct 2023 13:45:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697057131; cv=none;
        d=google.com; s=arc-20160816;
        b=R80PrZgrkvz3PxU1LzXU9Ynlkhq/mss8J0NkT71sBV9+yA15MOsU5wXi48PEWoRyHq
         A7ojlCoG3jVrcDIFnBbJj0ItcDBzDeMfNuEtcxta+I+lVe3vatm5GbUhyATVwJDLoZEu
         JIwX+XY2KwbNWUuiB9anDuJfG5+YccA/nqur789ra2aylZwijcBMObdgUsoENbtFUNo0
         rqzvRXBr9B21PZTE3TOYsHZt4CW7OHurch2tls3m7GzVldINNrQ+Ps+KOdEwOjTe5Uoy
         VWyF/6R2IKGb1EzuAgPU8rQv0nz2PawzZ346fJr4K/RNuNJwyShr5Nr/0xAGRNVgYIeQ
         TNAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=vF57FMszPTH1ctRnfsdLQnAKN0gbFWDA+OoyuLf2Za4=;
        fh=rJ8h3sxjJc+y8EYBgZD01cbd9o5icJkeDxe+3MZXRtM=;
        b=kXIqpA1M49kvehdqtjvgwqLXpP6454VsbH9+E67whrydDWZoO7b0nx6NAyrYlZis2H
         MO9TyUxcdqXkD3INki31R/M1Jp6HrzXEkHjrkkkmAEACRShrE0Ji9c3frjX1griOJmc8
         jRMRFxQ1f1ylqmcu3RDFyeATeI5+JKZP7jRg1nKCKrxCFQmVktDIAuL+dhr3eOFIgTc7
         TVMaOlyPC4Ea/B8M2/3kwDbs5Nrc3lxSfpuXJ3R04KoDuKX2v6mt7EUSVtQ1mEH7FvDu
         C55EiCt5Xz84Vqf5pUSWU3xn1dAPq6MdxvAOCxzXohV2oj3mV7rNMf+7zeCZYDs1F5AZ
         DMAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=K5DwM+5u;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id o13-20020a05651205cd00b004ffa201cad8si748311lfo.9.2023.10.11.13.45.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Oct 2023 13:45:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id a640c23a62f3a-9adb9fa7200so47318366b.0
        for <kasan-dev@googlegroups.com>; Wed, 11 Oct 2023 13:45:31 -0700 (PDT)
X-Received: by 2002:a17:907:7f86:b0:9ae:50ec:bd81 with SMTP id qk6-20020a1709077f8600b009ae50ecbd81mr16519816ejc.21.1697057130688;
        Wed, 11 Oct 2023 13:45:30 -0700 (PDT)
Received: from gmail.com (1F2EF405.nat.pool.telekom.hu. [31.46.244.5])
        by smtp.gmail.com with ESMTPSA id j17-20020a170906831100b009a16975ee5asm10059245ejx.169.2023.10.11.13.45.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Oct 2023 13:45:30 -0700 (PDT)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Wed, 11 Oct 2023 22:45:27 +0200
From: Ingo Molnar <mingo@kernel.org>
To: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Fei Yang <fei.yang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCHv2] x86/alternatives: Disable KASAN in apply_alternatives()
Message-ID: <ZScJZ7Uc6aJNyvRg@gmail.com>
References: <20231011065849.19075-1-kirill.shutemov@linux.intel.com>
 <20231011074616.GL14330@noisy.programming.kicks-ass.net>
 <20231011132703.3evo4ieradgyvgc2@box.shutemov.name>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231011132703.3evo4ieradgyvgc2@box.shutemov.name>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=K5DwM+5u;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Kirill A. Shutemov <kirill.shutemov@linux.intel.com> wrote:

> On Wed, Oct 11, 2023 at 09:46:16AM +0200, Peter Zijlstra wrote:
> > On Wed, Oct 11, 2023 at 09:58:49AM +0300, Kirill A. Shutemov wrote:
> > > Fei has reported that KASAN triggers during apply_alternatives() on
> > > 5-level paging machine:
> > > 
> > 
> > Urgh @ KASAN splat, can't we summarize that?
> 
> What about this?
> 
> 	BUG: KASAN: out-of-bounds in rcu_is_watching
> 	Read of size 4 at addr ff110003ee6419a0 by task swapper/0/0
> 	...
> 	__asan_load4
> 	rcu_is_watching
> 	? text_poke_early
> 	trace_hardirqs_on
> 	? __asan_load4
> 	text_poke_early
> 	apply_alternatives
> 	...
> 
> Is it enough details or I overdid summarization?

No, that's perfect IMO. I'd even leave out the unreliable '?' entries:

> 	BUG: KASAN: out-of-bounds in rcu_is_watching
> 	Read of size 4 at addr ff110003ee6419a0 by task swapper/0/0
> 	...
> 	__asan_load4
> 	rcu_is_watching
> 	trace_hardirqs_on
> 	text_poke_early
> 	apply_alternatives
> 	...

... or so.

> 	/*
> 	 * In the case CONFIG_X86_5LEVEL=y, KASAN_SHADOW_START is defined using
> 	 * cpu_feature_enabled(X86_FEATURE_LA57) and is therefore patched here.
> 	 * During the process, KASAN becomes confused seeing partial LA57
> 	 * conversion and triggers a false-positive out-of-bound report.
> 	 *
> 	 * Disable KASAN until the patching is complete.
> 	 */
> 
> Looks good?

LGTM.

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZScJZ7Uc6aJNyvRg%40gmail.com.
