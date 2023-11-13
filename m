Return-Path: <kasan-dev+bncBDXYDPH3S4OBBWXOZGVAMGQENJ23M2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 931847EA3AB
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:22:03 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-4084c6b4618sf106955e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:22:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699903323; cv=pass;
        d=google.com; s=arc-20160816;
        b=LIL7E5mBuMs5/h1Dd5UCbXRutWPh152ucTWi7hlrdWAtVGB3NF2Pt0fDeNjiReAtE+
         U7PBk3BXQbs5wfpFoyN5vqEZR7rHqDRLgmxz1Aar4MIK3Uc5xB6JaPpxz681xwhfDk1U
         mmLw7kNcrmSYgl5muyhd3Xsp59FPZaDSOiJ4b+cZ0S7FXC81x4d6TvJ9dYcifYVEWGXI
         ujPF8TaeBAwFlKwQkxVnG2JVGybge8LM+1H85Ks3saa3PfvotOM91IS6/pq94z46g/ho
         wWDRUumLO2LrbchYZV4ciwbXupRvf2nry2WMQxxlVsXhsdMzDMApzkSctfDadjIPd7jz
         bG9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=t2lcvRJgYspp5iDpuhtzRl/4+H25yUecIU3MdeLNOYk=;
        fh=D+IP4oYPxmK+rRGnclMPG2y1qrSbMoQ9qJToVmu6YLc=;
        b=TNLEBZHazsnvPTv5MnqKzhRwVoyX7CawiD664rNI5Q3653elCXfu/4bTdMc+MVblKL
         tBisbWbKpi9TXNFGPOviOUiMgDg2dzNpNr/zwuwzrLTCCO1AAl1Eq0/jSW8iwNHzPy0R
         0OTmSDgBfKc3hsML51k45PzeoLWdT7CWduUWf4iYscEmNQa7Mm+CK0nbGWDtg+vK+9AL
         Nj5otl+0yCCBd2K87K44LBD5w7NOfGKZHGxyw61cNpbeX0NblFR7Yxnc18fvJaPd+uco
         +DuuTCsLOaOvStvZGkRbH1/KpShumR5iwBhn0w6J5HlxA0BM7g2quf6JOcYg8dahoBlq
         hEgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=28lSfBuh;
       dkim=neutral (no key) header.i=@suse.cz header.b="DfEEX/Jg";
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699903323; x=1700508123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=t2lcvRJgYspp5iDpuhtzRl/4+H25yUecIU3MdeLNOYk=;
        b=fPO5ZeWZ6hiHNv09A7LouwUhp9LXkNVlFFEw6jmLAfBXlje0atyN7zrHpxMj3OPjsu
         TssNi1R/SlipwSGaPLFezK4/md1Xa1iA3ia6knUNx2GxjoqgVqpZWVlSjrP7KJqIrA3U
         CVLmB9Oo2sMkasZVUshMP1+7jhvUfYt/N63ARzqtvzoICjYiDgChfqjjuu4XyGndokVr
         t17IkokISmRg7J4WmpfiDct17NDIENMYtapCs4mqbkKai2IO5HHrKETZznRAZt/XrDoM
         DfIuGEte1328V6s4DmDkDORmz9yBVP6/2d3om/44vFZ+LFdjCfRPoJgeshWp00Scndwk
         96kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699903323; x=1700508123;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=t2lcvRJgYspp5iDpuhtzRl/4+H25yUecIU3MdeLNOYk=;
        b=Bes7wl0sT/aKSIy1eh/8AjjpHK2WIeblA6IVjkH7PSUlNtsteMkjV+m1ineLr+kxGd
         jBoyoJCF96hrcAOb0E9qHs2oeqWfveg6QRRk4RdEKwH+C+uP5N/TmyqYHdarx201KLbW
         l4+DhLPpoG+f8D1HbSXDlFPE06xfFTXQXf92/oKI7fLI/sOuoQEBz32fWuUe9w5Jf3zx
         Qt0HunQF/mefRncTgHi62NXeC+4gM5Ez1w51N9gjlM0O787/u/25mobahdcnH/YBLxKB
         1CCFIo6y7tolj/o/ceqeoUwKJltlLbYrQkdoFTU3Ine/ckgRCFxymtfUuvkutJb/cB5r
         WVPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywkt8JaexYvNidYUUBfh58wBZm51N/ehdqj6P4LeK9J8jQ6s9zk
	NR5Ao3AvyFJhKY9r+xE/dzE=
X-Google-Smtp-Source: AGHT+IH/hkhvRdgOpSZpyMmB+VLVINQqPhDfD8m35RXpfcjvntHszrB7y337PIUGXpMJJVhzABYZXw==
X-Received: by 2002:a05:600c:3c8a:b0:404:7462:1f87 with SMTP id bg10-20020a05600c3c8a00b0040474621f87mr24955wmb.6.1699903322996;
        Mon, 13 Nov 2023 11:22:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e05:b0:405:2359:570a with SMTP id
 ay5-20020a05600c1e0500b004052359570als2331727wmb.1.-pod-prod-01-eu; Mon, 13
 Nov 2023 11:22:01 -0800 (PST)
X-Received: by 2002:a05:600c:1d1d:b0:40a:3e41:7d6f with SMTP id l29-20020a05600c1d1d00b0040a3e417d6fmr6368082wms.32.1699903321116;
        Mon, 13 Nov 2023 11:22:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699903321; cv=none;
        d=google.com; s=arc-20160816;
        b=IogB4PplBFRhWpC0b4YbkAPZucFltljtUvpaA2hcNR31WVh3XAlqxKg4HsJwaVyy5e
         x7xEF5Ud9SWRTTzJEF/4gnF7Q+zjW+urwfGnt1N9TL/QJL6j2rHk6xCJVNnRawH/mFCK
         J+jiMneeKtgfagaB3Dc++7eTvGc5ha8MZ6BKwnmnXwkSzDYG4lwIZynek6t8oJ+Xp9Nx
         TGGbJGSF49BnMaczbqU+D2+Mbdqlb5XNp8ZwOny7ZkxODn0KXIIfX5Z+UyEoQFITi8Hd
         1hEha8TpIXKaRLOqVh29nJ+VKP1CYhzzAC/K1OG8COyO50i9KBeGBhUlxKZyaclIz2Wn
         Tb2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=adgK/oEUvJ96k3bu6IhQ1zQnzB57QPKsQCEOFsuv7V4=;
        fh=D+IP4oYPxmK+rRGnclMPG2y1qrSbMoQ9qJToVmu6YLc=;
        b=V9iQpY52R2/7GocGMreNrT/fgsp5APFUp4+GqJSal+mc/SOphrg+PKtjhblrrREPwm
         an0esl/S00cB700F0vwqSxl2ED8wLddtIHFX8wbSiAF82nZTrJnqUtBxd6hWN3FBKw7K
         pqbiwtbL8Z/w/sdLlyiDBt44aKCN587rids/0fBnb4THbLpcrGayr7iciGM2o9apwqad
         U5PFisvNPWdBDm6xqitFIPilvIzjjnPzpyOx52WTiiIoAEZZibGji6HxjijABN2OeH3l
         4iMG2G33xpOwfhCdfyH2OHJlhJlgM0qyU28anxS3Iu7wek0PXOmYHDxT1DjVVCF0qlUg
         4wVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=28lSfBuh;
       dkim=neutral (no key) header.i=@suse.cz header.b="DfEEX/Jg";
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id az13-20020adfe18d000000b003233224954esi251373wrb.6.2023.11.13.11.22.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:22:01 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 9E9D31F6E6;
	Mon, 13 Nov 2023 19:22:00 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3F7881358C;
	Mon, 13 Nov 2023 19:22:00 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id RQShDlh3UmWTPQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:22:00 +0000
Message-ID: <7379e9e0-1143-6310-0b48-8e8228701011@suse.cz>
Date: Mon, 13 Nov 2023 20:21:59 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 08/20] mm/slab: remove mm/slab.c and slab_def.h
Content-Language: en-US
To: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Mark Hemment <markhemm@googlemail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, patches@lists.linux.dev,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver
 <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>,
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-30-vbabka@suse.cz>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20231113191340.17482-30-vbabka@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=28lSfBuh;       dkim=neutral
 (no key) header.i=@suse.cz header.b="DfEEX/Jg";       spf=softfail
 (google.com: domain of transitioning vbabka@suse.cz does not designate
 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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


On 11/13/23 20:13, Vlastimil Babka wrote:
> Remove the SLAB implementation. Update CREDITS (also sort the SLOB entry
> properly).
> 
> RIP SLAB allocator (1996 - 2024)
> 
> Cc: Mark Hemment <markhe@nextd.demon.co.uk>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  CREDITS                  |   12 +-
>  include/linux/slab_def.h |  124 --
>  mm/slab.c                | 4026 --------------------------------------
>  3 files changed, 8 insertions(+), 4154 deletions(-)
>  delete mode 100644 include/linux/slab_def.h
>  delete mode 100644 mm/slab.c
> 
> diff --git a/CREDITS b/CREDITS
> index f33a33fd2371..17597621202b 100644
> --- a/CREDITS
> +++ b/CREDITS
> @@ -9,10 +9,6 @@
>  			Linus
>  ----------
>  
> -N: Matt Mackal
> -E: mpm@selenic.com
> -D: SLOB slab allocator
> -
>  N: Matti Aarnio
>  E: mea@nic.funet.fi
>  D: Alpha systems hacking, IPv6 and other network related stuff
> @@ -1572,6 +1568,10 @@ S: Ampferstr. 50 / 4
>  S: 6020 Innsbruck
>  S: Austria
>  
> +N: Mark Hemment
> +E: markhe@nextd.demon.co.uk
> +D: SLAB allocator implementation

Hm this address bounced, but I found markhemm@googlemail.com (now CC'd) on
lore from 2022, can I use it, Mark? Thanks!
Link to whole series:

https://lore.kernel.org/all/20231113191340.17482-22-vbabka@suse.cz/T/#t

> +
>  N: Richard Henderson
>  E: rth@twiddle.net
>  E: rth@cygnus.com
> @@ -2437,6 +2437,10 @@ D: work on suspend-to-ram/disk, killing duplicates from ioctl32,
>  D: Altera SoCFPGA and Nokia N900 support.
>  S: Czech Republic
>  
> +N: Matt Mackal
> +E: mpm@selenic.com
> +D: SLOB slab allocator
> +
>  N: Paul Mackerras
>  E: paulus@samba.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7379e9e0-1143-6310-0b48-8e8228701011%40suse.cz.
