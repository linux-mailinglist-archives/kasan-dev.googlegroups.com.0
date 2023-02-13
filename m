Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBVU5VCPQMGQEQZ3TRQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 349A36942B1
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 11:20:07 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id g14-20020a056402090e00b0046790cd9082sf7328393edz.21
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 02:20:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676283606; cv=pass;
        d=google.com; s=arc-20160816;
        b=SO/+iXPg0SUKqBWcdJIpcf5eZFqQSgS0MscnRbszTqs4eIbOwCFruDx80D53YSKO0x
         4FnZ/QOtyklcShkdO2vDsJJ04cEUkTmWyt9pVk6/x1qwjfo9oGKe1ppqTh32Y2RN00te
         biO+fTOP0SKzNJd8+SLX//tYExfRVeVwFkxdxKpJvja9DZeb7G73IOwJx2d4llalINL6
         ORQkpoKx3NK61l2986AS34iTIXUtgsgtjOR6JDcUi3ab6R3K9CRssGEi/tXwfGxpGlJl
         uIHI1GRLB89EvsHPNBT5D95io5878/nFz3La62rArkbTexy6Cu6rXx+6dnqRakCkX1Tq
         uBrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=6F6M/DmfMww9xIz4nItZ/Hijj8v65YT9ErVOBC774hU=;
        b=t4cJqzOECwu/hAseH3Si1YxnmkxHhsVfF5iKH67f+OhAWmzC/7lcL+dvhcMb2/zH14
         2mqT2pQ+VYr3z3E06RPM1T6xccCHhr8Fke/bCXef8fgHFboUKgRfRDM8Ydf0abuYrvwo
         qxXyVzyiT54cCn6bseUnNGB4QYL4yYzgobRV9lck+o7JmDFMo29XbKCPDV82W6SNcg2U
         jmfr0dXkVdP7PAtvkZ1iDacAFTvf7zScA3XeRdjjGBCQv6C9ZwfRXER6tQ7uRa+5nVf0
         9OB6Fxaixm7VtrL83JVspYyfjecMyIzEwHYrlXoVaGCA08t6jpK+KhQEtgN3DdJAnrfH
         ISgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Fu364rm9;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6F6M/DmfMww9xIz4nItZ/Hijj8v65YT9ErVOBC774hU=;
        b=dfC87xfPw9bChojz4tmI+E1sCrx0Ql1EYfOgAJYng14TOIQNJ0A3CMtkONi0kACJfx
         5r+zHjSAMStzgU6q9+vgTSL8q1o+tpZRAhS7EhP5LzEWL9E4i9dven7m5ftT/hzs0quL
         srmVaYqgIGyb25MXWEzuAGgG/HRv/doywYXRbZ5hiLV4Wj5NqoPg+NizJbG6ynggwcw/
         IgDWwy8yXQL7lWga0YbImrNPTQtkEcHJSQ91nAm7V/Dn57SA76SdWDF7c/K0V79NRODK
         5KVckwApZ95tlaTjpg9JpCHyp2eI6IGjhxuUC3Tsni4/DaaVq0s33ctXE8E7Vt9oS0J4
         jMsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6F6M/DmfMww9xIz4nItZ/Hijj8v65YT9ErVOBC774hU=;
        b=GLbdKS7ULwCI7+SEhRXkX+sqvhhv2RmVtxYeIu8yCBhHlc+Js2uP8Lyw+KPGtUpSNu
         lsYDqAz/3yGAtVf7Sf8D5hZJcU0kxEpLZlzTmrWoEINHPHxtQ9RB82/etKqCfzk5vt0q
         oT1kJA5d2CKkDhtVBuUXrshYetfcPDl4D8b9+3uGifdGWZs5+Dyce4v85xDpa7Stx0tf
         imwRZbpC25PpmbIfbf7HZvJe3qexj4fXmSydh5OvMDGhtZ6Sv5WM+FxsBajjaiL1LEFn
         OC75KFfg2yk6UWs/rzKiPQxAL4pXyIqZVsIiFxXd2B2pH2w474r5UbBtn8HHtvlhnKnZ
         ElFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXg4iWhBeQ6hbuFagrNG7CG3EAOOA69KNUOaEVBeJFJTnsWjGuQ
	hS/Hpuncze+LokV/A1B9dd4=
X-Google-Smtp-Source: AK7set+zlDcFNz7gaUuZovFgQSoPcQfgDbsIhwieafBUZVgZVsDbxEBJ0Ar8zphYpXxpkg6Qx7LryA==
X-Received: by 2002:a50:9ecb:0:b0:49d:ec5d:28b4 with SMTP id a69-20020a509ecb000000b0049dec5d28b4mr6551892edf.6.1676283606560;
        Mon, 13 Feb 2023 02:20:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2713:b0:4ac:b59b:6e28 with SMTP id
 y19-20020a056402271300b004acb59b6e28ls1166014edd.2.-pod-prod-gmail; Mon, 13
 Feb 2023 02:20:05 -0800 (PST)
X-Received: by 2002:a50:c05a:0:b0:49e:1f0e:e209 with SMTP id u26-20020a50c05a000000b0049e1f0ee209mr6782517edd.10.1676283605156;
        Mon, 13 Feb 2023 02:20:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676283605; cv=none;
        d=google.com; s=arc-20160816;
        b=AMBEzkicInhkhF3Usziy06U1SDXanLxpLjsuO8zeoOA5dWft4ppLpn7p3XAlHUX3a+
         sxHR//0N6kfhdq8Fl9bSM1CWhGuh0ylBhmZCR37qSmnk7cWR/bsUix9FnY7dsa/8x6Aw
         WW+n5buQ9Au74m5YvRYzeMljhAttOdOK1M4YZeTEvx1qRZadYy87gtXD80SAQoR0wfhk
         6EmT48QuK+kjqjzqvUhGpp6wZFdx6AELKn92kuMiH+OlVZPM9Htu3oGvBmANuFEbB20K
         oalAA2r6UkCKeHFaQAv4V/YVkAT+XEYdoUEyk/5UW2bcQFNu+TdRe1GaNRamXaRCHzSj
         viFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=65fYUfn3GoYatis0AOVMTqKcL936aMO9+NoqSfIfToQ=;
        b=jx/vmz/0EO/MEHQifu3PJUoJCRkZJHJcWHw0sm4r3GolbmBfmWF66IUygTMn7ly6OK
         VyZS1fWOogstdMCCbPibHxIatJltOUI3psGKSS9VtIoQhZ6pGQd3EVq9gApUHdzGdVIY
         8y2Y9pBOMnBqSfDNHJtwA7drOhaNjyroHDQowLdplSlN3uzcW1TvTIIbngWvAtpMTK4t
         +/Mqg2Efhq9QLPoVhBowQbqkMRatri/yhEu8cVHmOEud5jkY7hzeOWRO8BM144SmGcW6
         JkfmafWBABfa52x2kPAkRPAx4nrJwX2ROO1AwaC5Zpz5v4aKffdRAsqAw0+UjSLGAtyz
         doaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Fu364rm9;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id m26-20020aa7d35a000000b004acb6374876si272397edr.1.2023.02.13.02.20.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Feb 2023 02:20:05 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C294321B50;
	Mon, 13 Feb 2023 10:20:04 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 98127138E6;
	Mon, 13 Feb 2023 10:20:04 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id XK5CJNQO6mOpdwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Feb 2023 10:20:04 +0000
Message-ID: <2085e953-ff9d-4d2e-cb35-24383592f2c4@suse.cz>
Date: Mon, 13 Feb 2023 11:20:04 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.7.1
Subject: Re: [PATCH v2 09/18] lib/stackdepot: rename slab to pool
Content-Language: en-US
To: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
 Evgenii Stepanov <eugenis@google.com>,
 Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
 <923c507edb350c3b6ef85860f36be489dfc0ad21.1676063693.git.andreyknvl@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <923c507edb350c3b6ef85860f36be489dfc0ad21.1676063693.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Fu364rm9;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=softfail
 (google.com: domain of transitioning vbabka@suse.cz does not designate
 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/10/23 22:15, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Use "pool" instead of "slab" for naming memory regions stack depot
> uses to store stack traces. Using "slab" is confusing, as stack depot
> pools have nothing to do with the slab allocator.
> 
> Also give better names to pool-related global variables: change
> "depot_" prefix to "pool_" to point out that these variables are
> related to stack depot pools.
> 
> Also rename the slabindex (poolindex) field in handle_parts to pool_index
> to align its name with the pool_index global variable.
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2085e953-ff9d-4d2e-cb35-24383592f2c4%40suse.cz.
