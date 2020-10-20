Return-Path: <kasan-dev+bncBC2OPIG4UICBBRUEXL6AKGQELWEC4XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 37DF32934E7
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Oct 2020 08:23:03 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id e142sf734753oob.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 23:23:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603174982; cv=pass;
        d=google.com; s=arc-20160816;
        b=rW0RgKr2M5UBWDi872/SsZMbX5JZaaCAGhS7752G/AVJjvQkDJrKx7L3Tr/4QchqzS
         IAPw3fhY4CEGLLb95gU0VTQ/u0xTexU7N3fwytOqascP8DlDHjKSviJX3PImVm8PVOu8
         o0Wp1vensK2FEF7yvjdaziHjbbSxSePyCE8+LePC39ELro1O5Tu82vnF2U7eqFocqrDO
         n78orszxBJBRyWHUDBrIGNn8A3fGip7oHPByxPa1ZC1rEyRhQWLbjSNk8jDe2ACz5+Ql
         DDtNi8z7ad6bOaU8Z9Ju1s9bX+tB8DY5XBITiOzkxeXWbXXv6QlUUV4yxF6/mEu6sbcT
         b29Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=D/ZqURvHGmh5VxFQPiJ3ZXGxrwnr+E86Yvc0fkH2ou0=;
        b=1D5xLwG0eOuyVkY/kTcXej1at81lBdXreTafb3uCQxyLLu+gAd+SU81UiBi71ww9V0
         cg+pgHaro083LuKs0pr9BfIYtGTld6dpTaU546LpED4SKEXWfg+M+g0JTUI21syuAwcf
         1tmtldqhZ+BeNk7TpkAa1MZAuaaPuiOhBFVECoil5qWkJCeD3eoxIVUJYgYwXxP0YoBZ
         zZOOHxBl/oEV6rO1kS1dcWrP06UaJDJFTYzsqDzx/3DNNk+XgSHvAv9OVB/B0Lcojl2l
         WdlJX+YBF5KfKDzWLFEhc0m5vVfjDcfkLHYjXTcqDT5VG3UGeajy/IdzcAlNAwBIMPXN
         RdcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.18 as permitted sender) smtp.mailfrom=hdanton@sina.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D/ZqURvHGmh5VxFQPiJ3ZXGxrwnr+E86Yvc0fkH2ou0=;
        b=eG0TMNqTfJHvcy9PVQk4dwm4F+apCZrXqVu8VyBM4vujUOuhZPTG0+/z3PTPg4ErTT
         3Ub30e1zUgsSla8JZDaPqD8gDt/qDhhdyRqnyrnVwESBV2Iy8X9uX/j2Cwt1tWOfi/kg
         sPotKm+4JdLFzA4Ai1E/UZX+8HGoIDxBfYRY9oZ2CXr/CvOq9DV40E4CyYSUjfaDORo0
         GJ254pkyqtCJvMdicYM52J/+7Lu6lwxBfye6aLYFYotHjw+VM6EQFzKLgAYLcrehGwF5
         3F6l1cW13AQKdQX6rCmQBhTlHhmH8YNz36vxPxJKqaOnseO2Z4xYd6VMM6kH3b0JB6xG
         P6Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D/ZqURvHGmh5VxFQPiJ3ZXGxrwnr+E86Yvc0fkH2ou0=;
        b=My8LupPcnN1KjtAPsKAoYWrj5k5OCcEvoMYVhKCQfR1e3e3a7TJrBwLl4nDIsNjecC
         9k8ZhvknjvEzAQ/xj/6Fe5cRw6fYEBXY0rpckYBNGVJ1ySplHHA3kRsNC+W1mcQqnyCl
         Xeq7+/2nlHWd7AuWRTz91XRU0xLoAmnFOkgbJ3YMlWEUrj6EgQ4gyjyWs7GZQF/pZhWH
         FoZnBo+XobYc+SunjuUJRyyXyWrIUsujqPCyQSax6Rp4paX0OTLCEWMLkRXz/hn0TCeB
         0JohHgQULantbiAZi6UNR/W2Pa2s6pGkdRvcmhRNJlHEYxwhY6iJC7J2WN0qIgKqh8oZ
         FU4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532l+oHMnS6spycap0M/xiT6hSNNwXxJUsq7vInoxrcVFhkGK9xz
	zb/Fhc/aZ+CJEIco8M9dt/o=
X-Google-Smtp-Source: ABdhPJxqtdVMDksBLSRrZW87yAf/W4uXuECDIadTg8UwQx8wdrNycrTb30a0T3lLdUSxxKys05TmsQ==
X-Received: by 2002:a9d:61:: with SMTP id 88mr687251ota.109.1603174982203;
        Mon, 19 Oct 2020 23:23:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:53cc:: with SMTP id i12ls180579oth.7.gmail; Mon, 19 Oct
 2020 23:23:01 -0700 (PDT)
X-Received: by 2002:a05:6830:4033:: with SMTP id i19mr790905ots.127.1603174981847;
        Mon, 19 Oct 2020 23:23:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603174981; cv=none;
        d=google.com; s=arc-20160816;
        b=vTjIra3ckaNO/xLTfZ55sfMIAJ+wKohDomocFOmFaBLT73D4VJKvOiA4jtbsUFuK+T
         VikrKRc98CjO7Jw1lpCSJyLPwSbzZoIfTxiJu7bqq21ydXmft9OJVqXWlBlbg+a86dC0
         SWzA4Wb24RaRbgtyRLOZRcivjX1aEZOZIgN+O+O93LAtOtB4+mFF6ZnWw+iZAyZ0yu4C
         0pecmOvF2h0A4AoOeDBwbl33F/3iNnErCijCneSKUq7tCAwD6fx0x/y1J2WaUKA3hzGp
         wLifdBKo+VWWb8dnkG+cAq9gb7R1Ta1PQ6D0Md52lMtPogaRaLoluzrs3+J2RpoIT6nB
         TZ7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=YmG/RzcpJ92o3Py/BLG66/r26NGN1yC1a94JXWd1i/k=;
        b=eJw5j5qByzDdZZSNse0JykRzL9V107O75gvitCUwl8kAljvfVm+39uORqfJ4kCLNdd
         jq6U+Yo+4HhJBrvXiCoWJ6DYOYqN6mdlCHiJL1mb1PbEWdBSc8OGpqaJwbmmamy0n4Cj
         AH1yaGRAbDZ9yeciZEWVDO8Tc0ZeHCVqh3sLPndseaPLtUxo/UOiEb9Wmz/41bClzfCY
         uAIRvCgOdzy2c95BTMekATSM/nzOWNVHZnP/YwGtCPMZf5L06HhYNI2o+BPrZznlf4xu
         W8zbhHN7KeRycu2HECeuMwzpJx05nZ0zk6WFkIps0/DZTS/evVEosYPvD1caNWHsKff5
         KHkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.18 as permitted sender) smtp.mailfrom=hdanton@sina.com
Received: from r3-18.sinamail.sina.com.cn (r3-18.sinamail.sina.com.cn. [202.108.3.18])
        by gmr-mx.google.com with SMTP id q10si78202oov.2.2020.10.19.23.22.59
        for <kasan-dev@googlegroups.com>;
        Mon, 19 Oct 2020 23:23:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of hdanton@sina.com designates 202.108.3.18 as permitted sender) client-ip=202.108.3.18;
Received: from unknown (HELO localhost.localdomain)([103.193.190.174])
	by sina.com with ESMTP
	id 5F8E823F00021663; Tue, 20 Oct 2020 14:22:57 +0800 (CST)
X-Sender: hdanton@sina.com
X-Auth-ID: hdanton@sina.com
X-SMAIL-MID: 24493115073477
From: Hillf Danton <hdanton@sina.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Hillf Danton <hdanton@sina.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH RFC 7/8] arm64: kasan: Add system_supports_tags helper
Date: Tue, 20 Oct 2020 14:22:48 +0800
Message-Id: <20201020062248.1966-1-hdanton@sina.com>
In-Reply-To: <001de82050c77c5b49aab8ce2adcc7ed7d93e7ad.1602708025.git.andreyknvl@google.com>
References: <cover.1602708025.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Original-Sender: hdanton@sina.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hdanton@sina.com designates 202.108.3.18 as permitted
 sender) smtp.mailfrom=hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
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

On Wed, 14 Oct 2020 22:44:35 +0200
>  
>  #ifdef CONFIG_KASAN_HW_TAGS
> +#define arch_system_supports_tags()		system_supports_mte()

s/system_supports/support/ in order to look more like the brother of

>  #define arch_init_tags(max_tag)			mte_init_tags(max_tag)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201020062248.1966-1-hdanton%40sina.com.
