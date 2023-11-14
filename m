Return-Path: <kasan-dev+bncBCF5XGNWYQBRB7XWZOVAMGQEP6MHCPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C4E9C7EA9C0
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:45:51 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-67012b06439sf60971326d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:45:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699937151; cv=pass;
        d=google.com; s=arc-20160816;
        b=ErxV5wZZwRO4KPYE5lofTkepVejWh/NczwyhKBadhz12NhkVwX/0125MkfYktyPWXu
         vicIoykrgxFADWrIIfTi2QmaOp+BcfbiThnQqqDueN1S8fhg/TPWLH8ig9bzvQPvOdvJ
         yjLs2jtEh3U7FG8Ivk/5es41Viea8SdxNJf1XIlpB0GL60gqv8ePHFQMzAJWmC198Dwt
         5sajOJSSOFfJUXdVKiZbNE2lQly9S7oLChfmdyeBYm0lRQJqv1QuV3e+5pgzunSM5A5T
         nsdaanPMNzlNe60Nsp432h6J/x4LI0knJyJ+UVtIwnyE1nx+zG9AbxzZaQglJ/5QrXzx
         uTvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=orl8vbb/GdONnaOqmsTCPH2rnBHizkYdjikr5dD8cFQ=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=nlTKuIlejuwvtbZAWSqalf5qCwqEZFtqPBonjxpWcx4iJDwXVkj3ef59DgJKaIQc/2
         gljj3EXdG2c2+uvhtenGhJNrGns6zxaItdE5X/ZedOPslZW61xiB7RetyMqwHymEgbbR
         DHHzdHpQwp4+J7lhnLRrUAduXpZMT7IIuV4UEJCW5HqogHLzULdCJuLQhDzg/VU9b/XK
         sknoR5xGZ+7dmy0duc4OvfqZrBLzoKtP+8dadKVfHBVYBJQ7JFqjGPwdKoImPavRXyuo
         rOvkg51mxxOAKLm8NZzDpwTmvzhZAYuql50Q3U8qPCxu+9sf1SIXww76ZMsDPEmz8A0d
         m73A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=U61oYNW3;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699937151; x=1700541951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=orl8vbb/GdONnaOqmsTCPH2rnBHizkYdjikr5dD8cFQ=;
        b=NgH3HsSo0fPLZoYqgmQyqvxs5XH3RFV9KKNUGTcg3cMpCmYGldlpPkwQOHDpEsMUJH
         Mf+wT9QKTtcyqxFWLf/UYD+kbQPPqTZuX/RgvElKwMQnh4ZxhKcqTjvbfkjFgQum+r3x
         zIxshkCVJK9WhupNQ6bdo9Uhkr4iZTnEooo5gCd973SituTu467OPAXC1EcNJ/iA39kq
         80NTff6ylV9PSIG7Xix4w4yowar59dkoH8wUfzcYFfXYzB37+QZjCWfUvTvh99MrLwg9
         lHbVDmT5LcAKBjBerEzO8B5fgcN02dTTNqvvpsCErvue4lURdwcF8hNXHaLp9KFphmgJ
         KyMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699937151; x=1700541951;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=orl8vbb/GdONnaOqmsTCPH2rnBHizkYdjikr5dD8cFQ=;
        b=PbejH7SGwfZxX+x1Bh7DsINpLjZ+0Sa6c+KADjsmsxRF75gh+G8fUOo+tALGA5655K
         TAmUgybqNVxR1Y0540lonLVd1AnBcaEGyRVCO4Eqs+PypBWRT6k2ZWDSXKsMWMbOqWL+
         LdS4AGcfJ86WrHuxtXd2rVwQEYoANAnkQpKYtG5r45iihkbaMQBao542ll1U8D8dRKYQ
         PUE48kk8dt+/srOyMqW6v0DZ0jq274QQWvreTGkBPgkXnMVBarysI1l4mTXYX6iOjv63
         ITYLm1AzJr3t+/RjGrx2VlDXqCuPghib7FyjLbPbNDpc2ClWnVEjqrRDDGZtTxapcCgT
         Bxfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwmI9wER5JQpX7yaAB7NaaDoRNkVdFDlz/ds1aeYy3UqTQbrVlO
	nAltbs7OPadXRhgtx+urSQw=
X-Google-Smtp-Source: AGHT+IH7J0TSl9u6473KMGgFzhyyMvYWhgfVUBiqyByl0QIB0QLrKhz81dwrDc/VJVEVgHUiBK7V1A==
X-Received: by 2002:ad4:5bc7:0:b0:66d:8524:ebf0 with SMTP id t7-20020ad45bc7000000b0066d8524ebf0mr1752579qvt.15.1699937150791;
        Mon, 13 Nov 2023 20:45:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4dc9:0:b0:670:afd5:657f with SMTP id cw9-20020ad44dc9000000b00670afd5657fls1666064qvb.0.-pod-prod-07-us;
 Mon, 13 Nov 2023 20:45:50 -0800 (PST)
X-Received: by 2002:a05:6102:6696:b0:45d:906f:53d8 with SMTP id gw22-20020a056102669600b0045d906f53d8mr11407302vsb.6.1699937149898;
        Mon, 13 Nov 2023 20:45:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699937149; cv=none;
        d=google.com; s=arc-20160816;
        b=ZezFYawdADJ4RkHnwEZ8adQsU65o1/pyc4rycbEVSJucaW2dUZNwKGueIwzY3N15ll
         E62HBTSW0ARjKld4/MjCXoP8qDy5pSfSo6sV8dNOfOnnv0vRRs+UpgngB9RqZ8x+WJAQ
         UBtleBpVY/g1Lr93bo6P0itnKW+iBT6QV0fkRPWwwJSxsN/HP8AskY6j4n2hbsj9Ede8
         YG8s37sHm9oj+XkPsLQ/230Jv9S5YSjsKaww+qiU80FX4CL9RhSdsr8u/S1guGL/Jhsw
         ZN9qjD0CyRFbnZ88JeOu5G21ZJI5/MTk/17iYNAfWvz/xfPHLUQ2OyQ10MkfuxDqirsW
         9aeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZBMZCd1RTYcku4fr+eS/5T5vGEq4PYQLNXmfcgCc7wA=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=GI3fs3bhCWSMGJTVfTNpMgJjUd0ZgtBb+8uKwfbYbIz0dPIfjtVL39b410/n672CvE
         2N9JUo7caDBxDnBrI8wmMLzVRhGSKET5y4l0fm9pIzVHCaHA7C8iWSzaTA4QGYeUlKkc
         ExQx3prYHQL9XtyLv3zA/vptxyLwgmUfCvY7E4MRcSapZTrueMsxLE/4R2S2sH2xAwv5
         6eqqAT9ja8OioiGrPEcJYyRdSgQEKWUhIq3jMyt1aHvrBZXdMPP+0Qqirhb7Ls3VsnuM
         w++XFIU2+EhtoNRjWMbU/qCwQnKIjJaV11ehvizOcqJiuApWpziyGP+R2EfSDGa7xSOq
         FSHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=U61oYNW3;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id cd12-20020a056130108c00b007b5fcda34aesi868480uab.0.2023.11.13.20.45.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:45:49 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-1cc3216b2a1so39764615ad.2
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:45:49 -0800 (PST)
X-Received: by 2002:a17:902:8542:b0:1c3:1f0c:fb82 with SMTP id d2-20020a170902854200b001c31f0cfb82mr968412plo.41.1699937148885;
        Mon, 13 Nov 2023 20:45:48 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id u12-20020a170902b28c00b001c55e13bf2asm4804097plr.283.2023.11.13.20.45.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:45:48 -0800 (PST)
Date: Mon, 13 Nov 2023 20:45:48 -0800
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 15/20] mm/slab: move kfree() from slab_common.c to slub.c
Message-ID: <202311132045.D84400ED@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-37-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-37-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=U61oYNW3;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634
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

On Mon, Nov 13, 2023 at 08:13:56PM +0100, Vlastimil Babka wrote:
> This should result in better code. Currently kfree() makes a function
> call between compilation units to __kmem_cache_free() which does its own
> virt_to_slab(), throwing away the struct slab pointer we already had in
> kfree(). Now it can be reused. Additionally kfree() can now inline the
> whole SLUB freeing fastpath.
> 
> Also move over free_large_kmalloc() as the only callsites are now in
> slub.c, and make it static.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132045.D84400ED%40keescook.
