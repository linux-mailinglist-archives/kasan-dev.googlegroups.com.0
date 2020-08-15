Return-Path: <kasan-dev+bncBCF5XGNWYQBRBKM74D4QKGQEKWJV7NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id E552E245178
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Aug 2020 18:39:06 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id s14sf1916676vsp.14
        for <lists+kasan-dev@lfdr.de>; Sat, 15 Aug 2020 09:39:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597509546; cv=pass;
        d=google.com; s=arc-20160816;
        b=yQJkwqr/79WyKEpHGEbsTvKV4ztd87l4ck71+S0/RnEDhrLRFeK6oGQYEsjNDdCVlt
         kONA3kKu6S3QxGUN3ZFq3JFYsFqf1GlFahX4kJvzhom2xt6lYEaPDhYuoyuAwHxfguF1
         wGoV5/LwoynWV8+NtBvro8sRkQ9jJ+3Q9mP0yxhSwOuENAzQQbJdQZ641NILR9jyIJjs
         MC6MjjiZRIzqH57ipxlYsmznJRe9BYWn8XYsYV+4+wr2w6bl0CgagZ0Fi4d1Uy7loK2u
         7OOFBNHZ8HQ6Ve1gbBSM7BWFC19xtagHQ0dqVQOmaw1U0gHYLHyLxPsbry6vpuP1DoWz
         zP3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CrNlQ8oZk0KyaC894QFfbEpFaLzBJihJ4/cBHutw2CQ=;
        b=SKv9/D3H1G/iZmFuvHTSNNuGtHf2k3moMnSact7syjg5X6RFyUpcGm8BayKwKxa30m
         Q9XYf5nG1XF4PPyWlDrKYsWqbCRCik7t5TJ4gXAkdBiDFggAPTxlauNd3FGn7MlTI4sW
         zhJL+7EHBeywqoQ2gsyb42kOx/Ywbr44fzQsh7L/zr0gy/DDq++/Gk2ZJaBvdTTuqbnG
         JCOF9fwpt/Ec8CBdX/BJ2/WpieF2zh+eDjzL2Y2X1/cIylq9GDMi3u/Ee0bKb1WOb0ik
         P+6dzEBoKpwPlPGdj00FWbIDI3oSCUvjfiQ8jTuIKVbxu2qtaID5YS9hYXBJ1I7bZe0s
         470A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=hyCX5dk0;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CrNlQ8oZk0KyaC894QFfbEpFaLzBJihJ4/cBHutw2CQ=;
        b=HeSOrF7EMNzqmVVxrgj4wbIg6ZCmQ+6vcOaLPf939/AkyEGmqNqQVeC+RJb5MGoR6u
         OzyNpnAJxYOVm0OOAKrnDrllyWxVZ/K3ugl+tpYC1A72W4bia0kpQ8INmZo7VWU8pXnq
         VnYhewG9cI6Nce4dAs3Cftm5m1bA/AEiS7uqqebmMQpd/eWm0D5Cy7uO28BhZmqRhYNt
         55477G1aqM8YsqznQdXL3+lPHAtUHytZ+m3uPD/CQv58LN4YEabnHPPrPsA8ECxZrqRL
         /TqrdE1vzwjNqkyGqdUdl9LDY7SP3MSTZ9JImg6CiFiOuZeLF+1qb5PJcw0cBlpkBKaH
         T/BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CrNlQ8oZk0KyaC894QFfbEpFaLzBJihJ4/cBHutw2CQ=;
        b=IocfjzjQRbax1knUKvVeWEc+zNObxyTQwDa7WjwLAJITRHaANk4rS5mKWVbA0pzsHb
         5pilhXt1bBBMSBar6LsJAjV6o4bLQuen4lmPbVCXq6aMiyDKe8IgPOSUKWr6AtL12wgh
         Y5VmF9jP157Jl4Xjv2oh4scavQxRgMDtG9ZcxaoSKZXLJ+v9RhzyTuUDsQqfLF8bS4Nw
         EHTrYTiONihLbKO5s24TW7y+cScc0RR8mezPRz4+e1W+RTNdpWu4qXWtWSIbGjFufWd0
         ioJxGTVSfEQgCXNt6Jn6kkrCi1Cfontxrn3K72C71AUK6/WaTZxh+4hkKjY2QWw7sLOp
         7G+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531s3XKEfyjwY2dTOUo06C720RL9VE/aJml94b3a+3wgPTxRZKw+
	kopN4Dk8lsdXByw6OcIlC/w=
X-Google-Smtp-Source: ABdhPJwpuo5TxG1KgRYAwhF7ELsuYUdUlNsdWEE2ldYyW1Ts4qfQesMG8ktk6IldXuiKeO4JHyswxw==
X-Received: by 2002:a05:6102:213a:: with SMTP id f26mr4460818vsg.6.1597509545991;
        Sat, 15 Aug 2020 09:39:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:cf4a:: with SMTP id f10ls1420021vsm.3.gmail; Sat, 15 Aug
 2020 09:39:05 -0700 (PDT)
X-Received: by 2002:a67:2d4d:: with SMTP id t74mr4752783vst.111.1597509545644;
        Sat, 15 Aug 2020 09:39:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597509545; cv=none;
        d=google.com; s=arc-20160816;
        b=egsk5r5O4ugGhG3Ky8OdEcaTmYAgX7egIwMb9u8mqAXkuxE5dkSObH9SmwpMEZ+N5D
         t2is60XQ7g9ZsiSOvg8QSu0MO0CzPvh9Ee2fJp3iPvDfufgdZxiFXW8OAyksxLE3JNAm
         dQWqUVGRH8iAsVvFlCE/ad5K8jGVTZ1JC7nvF0zM771sP4jVetQEWh9jXrCwdlSF5sCN
         vktBNQsANqyQM/jjyDSGw8ZZexYmXD6bI8mf9+4JNum4KHMEzKVPpEbjjC9hHMxoBjbJ
         GT3/bZxNDtgt3KUDHjgmLHZ5QFT/Q2naBiH8SmdYZEcf+oRX9cSyYFR8hPMbu5wdajaz
         hT+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4J3Q2ehkUro4Gqm1OJFrAMNOhAG6pUBKwcsUWslCw24=;
        b=yuDZ5O1ukhECFeyndTRscbvO4gFjBlIwp+XOxZTqSSgqYpDvyCeO2LeX7VzrKib85q
         +AIcGw/LF6ziRxD0ad4bgInJaxdajy+vBisPgW/JkVjZSEqfPXCw1S0Sy15kcrLFH27U
         PrETYfTqCKhVrtoU5AfEtxSCqWVoUvgiFVG5EA6Xge/ihANRqbT0noVk23ymAPXyME32
         TBYrjDeF1vSvc/qOrVHC0MtqkitnBnLLPm4MciEStxOKX9iMYq0TnxwlFje3CmmMzflF
         MiANn3AE1lJ2ZiagI1RSweq977WfFFEuQpj2Krbz5DU2mb/q1z9y/twxyvII1rOa3/jF
         zQsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=hyCX5dk0;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id j18si942235vki.3.2020.08.15.09.39.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 15 Aug 2020 09:39:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id t11so5500548plr.5
        for <kasan-dev@googlegroups.com>; Sat, 15 Aug 2020 09:39:05 -0700 (PDT)
X-Received: by 2002:a17:90a:148:: with SMTP id z8mr6733727pje.197.1597509544802;
        Sat, 15 Aug 2020 09:39:04 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id e3sm11269389pgu.40.2020.08.15.09.39.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 15 Aug 2020 09:39:03 -0700 (PDT)
Date: Sat, 15 Aug 2020 09:39:02 -0700
From: Kees Cook <keescook@chromium.org>
To: Alexander Popov <alex.popov@linux.com>
Cc: Jann Horn <jannh@google.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com, linux-kernel@vger.kernel.org,
	notify@kernel.org
Subject: Re: [PATCH RFC 0/2] Break heap spraying needed for exploiting
 use-after-free
Message-ID: <202008150935.4C2F32559F@keescook>
References: <20200813151922.1093791-1-alex.popov@linux.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200813151922.1093791-1-alex.popov@linux.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=hyCX5dk0;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Aug 13, 2020 at 06:19:20PM +0300, Alexander Popov wrote:
> I've found an easy way to break heap spraying for use-after-free
> exploitation. I simply extracted slab freelist quarantine from KASAN
> functionality and called it CONFIG_SLAB_QUARANTINE. Please see patch 1.

Ah yeah, good idea. :)

> [...]
> I did a brief performance evaluation of this feature.
> 
> 1. Memory consumption. KASAN quarantine uses 1/32 of the memory.
> CONFIG_SLAB_QUARANTINE disabled:
>   # free -m
>                 total        used        free      shared  buff/cache   available
>   Mem:           1987          39        1862          10          86        1907
>   Swap:             0           0           0
> CONFIG_SLAB_QUARANTINE enabled:
>   # free -m
>                 total        used        free      shared  buff/cache   available
>   Mem:           1987         140        1760          10          87        1805
>   Swap:             0           0           0

1/32 of memory doesn't seem too bad for someone interested in this defense.

> 2. Performance penalty. I used `hackbench -s 256 -l 200 -g 15 -f 25 -P`.
> CONFIG_SLAB_QUARANTINE disabled (x86_64, CONFIG_SLUB):
>   Times: 3.088, 3.103, 3.068, 3.103, 3.107
>   Mean: 3.0938
>   Standard deviation: 0.0144
> CONFIG_SLAB_QUARANTINE enabled (x86_64, CONFIG_SLUB):
>   Times: 3.303, 3.329, 3.356, 3.314, 3.292
>   Mean: 3.3188 (+7.3%)
>   Standard deviation: 0.0223

That's rather painful, but hackbench can produce some big deltas given
it can be an unrealistic workload for most systems. I'd be curious to
see the "building a kernel" timings, which tends to be much more
realistic for "busy system" without hammering one particular subsystem
(though it's a bit VFS heavy, obviously).

More notes in the patches...

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202008150935.4C2F32559F%40keescook.
