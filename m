Return-Path: <kasan-dev+bncBDH7RNXZVMORBWHE76VAMGQEYAHFBHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DA287F69ED
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Nov 2023 01:46:18 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-421a7c49567sf366971cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 16:46:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700786776; cv=pass;
        d=google.com; s=arc-20160816;
        b=QXq2nbxKq+SHcqfrHUt0cCPHUEmYRCuJsFj7SPU0xbuYbOG9ulWlBR9EsUfO0I6X1n
         kDLDiHt1p6Rvj5XMnBz6MG+nubdmw8ySFRtZWB63Y9NZ0kbB+Y/TRf2eMoxv/ipaPfw6
         GlpV1eAfoJLrbhjRrj8iu7IXv/mcLSN0V5PN7tni4aQKnCUGitd0veQAKRv/Pi9Q0xs5
         jAnN4JZ8pURVMIMrhPkdMFJvznkXu346tuvNU7Q0VS1wi8IN1xrWtK7F3xDqNDHZBiFQ
         9tVgWbHmlED4lWsfOEmdKZ+hF9Uw4Pufoi9q4v0CyTvdLzEKUD7gOe6oYx+lE6rJnKdn
         hsLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=frTrEsDg2f9WgTq5uszs8QbIQMqw+wM3jHaYmPlOpW0=;
        fh=iuLdO6hgo4itszUZXIqScSL1V/nHNBgWgGCxa/vqvpQ=;
        b=vQZQ3xYVRupazu3KRIlHqMjkEmWjtihLFEX+eILsWHlItWoqcjZz4zVxGGChAp+F1e
         oShgltvFc7u5KhI2qTx8ggqoHX/GN2B5cP7BkQWwuBQsPtKd6OSpPjR0Ui+oAx2lwrRB
         eRt8QJ0Y0bgwOoH8ScISBmoF2c4Bt6Z4om8aY5FPa9AZr1wiXqF8IFvgDMLt5e8EvYlv
         ncHWMqAccF9x+6ACl9gHHrOi/CzHAasC+lFWPlTo0Gw/fCnNqe7DlVa0keBFrNooKNUj
         ryJbs5kwlWvX+R3XW6LdPSKMn9i1BBCmpUHXNdUJH7DU2H2UhtEYfKbSM82Fmav6nlDU
         V1XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="LDTC/6Aq";
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700786776; x=1701391576; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=frTrEsDg2f9WgTq5uszs8QbIQMqw+wM3jHaYmPlOpW0=;
        b=C90rB6yXFHm6viTQlj0I0VOIf7Saes/uKqcr5zS39o3swpzJWDptpwjlwfU4AkiRwy
         Xk+ibh9iYmLztmffHg8swCAnuaiHWVQWoCSA9fREQ2qw/ymEF8R48Ssp8frvazuvGJi2
         4wikTB4JftkHRgYeThIIupzEBhLChRSj2UxB6Ha8fRkXmidMtq9yb0FHrGGZ/QVAMERI
         cWslZlSxFSXK/WSfa1ccPR4wH/s7S4SxwAdCc3P8HU994tPcO93aQpreGsdfMsWYRRKU
         td/89d4R1HCgiG5alSeF9HKTYspgtLdhm4ssG/TUL0pLxfnU7zNgG6GWWgnHz0ucwH1+
         4Bdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700786776; x=1701391576;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=frTrEsDg2f9WgTq5uszs8QbIQMqw+wM3jHaYmPlOpW0=;
        b=uVDrtOn3SswIiCQq26sg+ZX1pedReEhF7H1slMlfV1EK9+wYwRClLmHzO9ai+EebVq
         vS19kOGfcvPnPGYWUyrcfKuOper9hrFI/q84IT5dfQLmJW1+PTp5ghNBeBxyi6FddGtE
         YE4xf0KL7z2BZefi61Q5bI9qqRTNJ47aHPb7DM4TyhVcDn4EeNkEcBFw9xYEcjZLH5uA
         x/03A2fELBG8ePNwDWzJclqDd9ixGw9Fz9Wd7O+JtYdJfA897iLVGyxeirzZSdqJV1rA
         0O+tleoPzx+vrR4LEIQbBHHkMcbPHi8g0xDChfkJoTu2RYnMe6sp71GQUZ8vhw8qc3Ep
         TDrg==
X-Gm-Message-State: AOJu0YxQJQkfgWD9ifqTeuIoAyD8qTYEC2PlhKjvJHflVRJ1DzlXo9eD
	X5zFt0ifCoZSEYpRvkppees=
X-Google-Smtp-Source: AGHT+IG2Yewg2C9y2eb8dU0F5MsRNG5eEaYB2+TNEzLTjTyvDHIUssK/IkMnJj34nd17tIT/hVjRVA==
X-Received: by 2002:a05:622a:1109:b0:41e:3778:3389 with SMTP id e9-20020a05622a110900b0041e37783389mr545393qty.22.1700786776549;
        Thu, 23 Nov 2023 16:46:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:58d1:0:b0:423:74ab:1ef4 with SMTP id u17-20020ac858d1000000b0042374ab1ef4ls1632863qta.0.-pod-prod-07-us;
 Thu, 23 Nov 2023 16:46:16 -0800 (PST)
X-Received: by 2002:a05:6122:1807:b0:49d:9916:5747 with SMTP id ay7-20020a056122180700b0049d99165747mr942048vkb.13.1700786775833;
        Thu, 23 Nov 2023 16:46:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700786775; cv=none;
        d=google.com; s=arc-20160816;
        b=hWmYmiK3PNJ1iCfqtw06gYAv2SjuDd7IzDa9o3wFeDF6+643LZc1PW9KpGbB35+9U/
         MAgK39FzGUAa2I+gPU6qU2xcsQsyGtCnTUW4ZtFCtTgok1IBEVe54alICl72lxGJr2vQ
         csQWSrFOCWefy/pNmtCstWJKDapKCSEal5mzIKCz52wyYRguvPz1w381V/m8Kt4NCUkv
         IitpCbxg4MmB2sx2rgfwdQcA6D0gH5Qh59FIpa5oafALz8ocqgNJgRxkgHUPDq6wz0xy
         hzEtyT2+goMFXmx5zlwg6jd988rd3dPYAKzVJKresdtUAGMogDlARcAWWJlAmvToQkeb
         qtMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=dyESJhHP/pA7tKXWx5D4jkhxltBcaPXfc9yFdB3lYZU=;
        fh=iuLdO6hgo4itszUZXIqScSL1V/nHNBgWgGCxa/vqvpQ=;
        b=Uu0W/ViIm4T6i/jSawuut7lDdNJ8sAkWo4TgnscPhW5J7QNDnZHrPcDhcFj2jLecdd
         iFbUHsI8P1wGLCcxgp01bpLjeqW04WEfNk3WtuyE5BipRXKssELEDCcQ5D6wmAqFT/V6
         Bi45WYF6Z9TjbbD259N5eoLvnLhz6YWoasz5CBKVMmzgKE/oT+dlj0PhGiY50qoRPK81
         Jw4gGKkyZCedC4KjAPLj2x1hdz7+4fvCIryem34kxrVuRDCN2KW5kbvIL6eKNIZ8SdM8
         CZRPTzl6kIqvjTSeLFoE0NbjxwLQGlyy/+7GaznrgANe8PU8W/EyyLhgMOKwSl6GcHNy
         CVrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="LDTC/6Aq";
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id cw36-20020a056130222400b007c4705fb21bsi98003uab.2.2023.11.23.16.46.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Nov 2023 16:46:15 -0800 (PST)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-1cf5ceadfd8so246695ad.0
        for <kasan-dev@googlegroups.com>; Thu, 23 Nov 2023 16:46:15 -0800 (PST)
X-Received: by 2002:a17:903:1245:b0:1cf:6573:9fe0 with SMTP id u5-20020a170903124500b001cf65739fe0mr609687plh.16.1700786774750;
        Thu, 23 Nov 2023 16:46:14 -0800 (PST)
Received: from [2620:0:1008:15:ab09:50a5:ec6d:7b5c] ([2620:0:1008:15:ab09:50a5:ec6d:7b5c])
        by smtp.gmail.com with ESMTPSA id c1-20020a170902724100b001bde6fa0a39sm1951963pll.167.2023.11.23.16.46.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Nov 2023 16:46:13 -0800 (PST)
Date: Thu, 23 Nov 2023 16:46:13 -0800 (PST)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
    Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
    Roman Gushchin <roman.gushchin@linux.dev>, 
    Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
    Alexander Potapenko <glider@google.com>, 
    Andrey Konovalov <andreyknvl@gmail.com>, 
    Dmitry Vyukov <dvyukov@google.com>, 
    Vincenzo Frascino <vincenzo.frascino@arm.com>, 
    Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
    Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
    Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
    linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
    kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
    linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 01/21] mm/slab, docs: switch mm-api docs generation
 from slab.c to slub.c
In-Reply-To: <20231120-slab-remove-slab-v2-1-9c9c70177183@suse.cz>
Message-ID: <ea6d3060-1517-6eac-8939-1f3d004cef1a@google.com>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz> <20231120-slab-remove-slab-v2-1-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="LDTC/6Aq";       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::62f
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Mon, 20 Nov 2023, Vlastimil Babka wrote:

> The SLAB implementation is going to be removed, and mm-api.rst currently
> uses mm/slab.c to obtain kerneldocs for some API functions. Switch it to
> mm/slub.c and move the relevant kerneldocs of exported functions from
> one to the other. The rest of kerneldocs in slab.c is for static SLAB
> implementation-specific functions that don't have counterparts in slub.c
> and thus can be simply removed with the implementation.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

This is new to v2 so I didn't technically get to test it.  But no testing 
required on this one :)

Acked-by: David Rientjes <rientjes@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ea6d3060-1517-6eac-8939-1f3d004cef1a%40google.com.
