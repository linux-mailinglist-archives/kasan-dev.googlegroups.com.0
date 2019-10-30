Return-Path: <kasan-dev+bncBDK7LR5URMGRB2N443WQKGQERJP2VHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 03298E9D8F
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 15:30:07 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id l9sf1769062edi.8
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 07:30:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572445801; cv=pass;
        d=google.com; s=arc-20160816;
        b=FbE/izLUGUYovDGapmW9+zDJ1YUiCm8e93fgNxtx5SRrBpTPZIZ/peW5hfc3cw4MHf
         5m0xZ0T2BJjq8b6CH3eTycfqnxUtaVffyEDSLYaklIrR2jygOQb2MQfzCzgzRSrRULgU
         s9anMUUGYlsYquLSR5cEkGwuyTqLutY9/o7gVNPpzBfjdwNxFvTvbxNK56AAFpVi4tXU
         B1rSiP4B0fIu9ej5rWw8X/lyl2zd9saETnNLY5N6mLhZsibeu/MpK5puHJbdfX8BvhQF
         OG5EY+GKXilVDSVBgmArk/4ghFMUDWq68ndUl9ZGKlXzX7dyned0jnLlCX5kbBwBpiii
         cr5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:dkim-signature:dkim-signature;
        bh=ThXouiWYvlZ/mTRGRuKxssIUi2UPu9MKsjg8I6fGtRw=;
        b=huzvrQIOFHEA3hzVABi71Q0ktfGb4zdy0QsExE5y9KCQEBbWKXUAETi2pFZF/HgjnS
         TJVJo65rpbYlC8AZDdyfh/+JbKOdaXmAl7CbKmXXjh0/iKbKAytt4cfqNv8oj0OXq+B9
         wBigLGYI4jpklxPGJgbxtMc2z+kWerqyfyTHvFEdIIZaogVoLDnybMeL2NiFgnBIzOMB
         /kKkIAE0lg+5F9OeK1zWUDx7EGOVA9UqeT7YZvvrk/MpGrFrvJr6cd5d5Ne70snnxVbs
         BaSa3S5G3u7A6QLPhV0f4WYXZh/+brDKsmrqPGIdY9CUPluqWylWh++RpxTYQJXhO5xy
         E/Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=h0t2hUb4;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ThXouiWYvlZ/mTRGRuKxssIUi2UPu9MKsjg8I6fGtRw=;
        b=Qo4FxaER6RVK34mk6T5ylWhUWc03IwZWAM5DonCFGSfqYDgPkQLmu0vWx6kmY+Wytd
         bhUj9DLPyRDgw1UTo/X6GhfWH1XPn6H31qJufm6k3EZMbmKXrqhcFJ1J7F/0smgl8eaW
         TUr67V4U+i+HhDLgVCe1RvNETw7HmPAh45uX0K4LfmcgL63/6XBeN76WRt0X+nHrwUck
         uh+Gt6aBeV/+NXYA3Di2qAtkT8ZsLpoMR/oqBZnPn5s2csaIW1Wm+qbhcQemI/3/fYZ0
         yZKPi3wmKbJPtHF32cv6tNG+JFcQi7vbkwJN6ubT58wTDdy2QUaAODengAuqDhReVq/t
         evDA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ThXouiWYvlZ/mTRGRuKxssIUi2UPu9MKsjg8I6fGtRw=;
        b=p6ftLtCU8R4EeK9lJsLhpSRmbAmJxMoirBQ4Mpz/08G4LdeuvDah8RYY+YksDhhgT2
         t5MSm8EP65vWP+kI9CEStj4V53XK98YVhx/vMwptk4VDmsqumciDZjDcbvVl82+j+2JS
         ZyYNz5N7X+ROyzEblvHxFmfzvUg3TE/fAQpDWgkyGRV6zbUuYRvA8il2/8X1WUq+odvI
         R76grkzvc3QwUuS25McCT2ClEFXzGr7Df9N/2cWecdnpCgy4d+MYaSWEj9fj4t94JRjz
         VVq2hYAYOFCQECP1QN097mD8IuR70bxqHTGFCHd12GAxfLZRgRMulkU2WWgMTegn2j/Q
         oh4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ThXouiWYvlZ/mTRGRuKxssIUi2UPu9MKsjg8I6fGtRw=;
        b=emuaMqI/wGcb62hVpyEcqHk2yBdwXa+VL8WIG0jSlgGRJJi5f94XZTjXUJsW9+oiNU
         RX7m9Gk27eHIBZq52bFXC8k8a7WlA2gtRvC2NNaLXepxOgcj54rF5Y7T0CrgFAI80Gpd
         iVdujt0IExDT25t2BGn9u8ANm4dLHAWWEVW2oRX5ZL51CeynLhGO1hQdc6kpiFuwVLNR
         kWyLRdRwL5YL3mLVn42pnayl+iQUnaFQbiN1WKpgfCL5w5WRz8GkKxPv+2cTsz1flnN8
         En45Qh4HKwhQa5cG2hMWJLoPl5qupKxfXmvmL+1YxZm2+CBMOmRASNUNXqFW5qbO0g6B
         xHfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXlNzjm0wVnvcRIfM6gNcJrYx4Yugycl8gpzTl+ELi1Lv52rZe6
	VKryuivuLpjP09kNcnIq5x0=
X-Google-Smtp-Source: APXvYqwej0oUI8bsHaT/oPRLZ4njeF54sYE1GtDqIEH+BRtcwmJskG/w0Fu0bTpzlkwtyaIFJJZXJg==
X-Received: by 2002:aa7:c1cb:: with SMTP id d11mr32384272edp.40.1572445801556;
        Wed, 30 Oct 2019 07:30:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:6a4f:: with SMTP id n15ls4818812ejs.0.gmail; Wed, 30
 Oct 2019 07:30:01 -0700 (PDT)
X-Received: by 2002:a17:906:494e:: with SMTP id f14mr9551972ejt.42.1572445801090;
        Wed, 30 Oct 2019 07:30:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572445801; cv=none;
        d=google.com; s=arc-20160816;
        b=hBE+ufMWo6Ua3nmFJkHUNHokDfGXBOHpNJepJJKHOyBhBQcQfcjjddYv6PLnSkxvyS
         SW/m05KJ94Fs3bcLi7hwpa2A5dezBye9wpMLZ/cdNO/pmL32udn2wWOiDgrcmdwhCKAG
         jrDNgjQ4RYi2427zZsF14pgwurlg1A2AxcAwqEOdKYH47j/iB0hvgDaeSzQ3t2dPVjhS
         aIJNVrof2hmQrje43SScNzuPzgvuYl+GJxXHI8yQTkZQLXIkpE/UGl9O5+aEUKQZe7CA
         gniyBhPIkGfTeprIniR9YC/NMtA+9dH9+pG5UordsJzSNcCDM4gHAyN3uT4At+A/fA6L
         9eQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:date:from:dkim-signature;
        bh=UDQi5D+Jni0obEk/hrjnnpFb3HIzP7e6/KmAnzzfUzA=;
        b=yTmfq1OHKlXXYPBBmqM+ya8prOtjv3syT+82apsOTb7pYk6MDWOrx3/CyoR2qXVp4l
         dLr9IHkVSD4mBh43Arhbr+HvfRikOFmb73Zo6Nyv+mcFQDhsGJAzJugfw6OTNOlpTPAX
         9Ldx7ljaI/V7oyCM/ZdKlnk2dJfEshOJD86AYUXceXo1R54dQrEQCzdenCPrmtRBWyUi
         piHuKJR94l+8akqGy8rUe+31RUKd4DJEEdCIYZWx4LsQpaZuhWdcu+fldcVyVp9fwyv8
         lTT+tjn2/P1JLg6p9kdKhzKYmaOo4O+yBfz/Q6txzqcjPm9K2sLP8t0RUHu8++LxGBV3
         G87A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=h0t2hUb4;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x241.google.com (mail-lj1-x241.google.com. [2a00:1450:4864:20::241])
        by gmr-mx.google.com with ESMTPS id y21si155215ejp.1.2019.10.30.07.30.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Oct 2019 07:30:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::241 as permitted sender) client-ip=2a00:1450:4864:20::241;
Received: by mail-lj1-x241.google.com with SMTP id m7so2945157lji.2
        for <kasan-dev@googlegroups.com>; Wed, 30 Oct 2019 07:30:01 -0700 (PDT)
X-Received: by 2002:a2e:8545:: with SMTP id u5mr7565ljj.213.1572445800371;
        Wed, 30 Oct 2019 07:30:00 -0700 (PDT)
Received: from pc636 ([37.139.158.167])
        by smtp.gmail.com with ESMTPSA id s7sm32320ljo.98.2019.10.30.07.29.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Oct 2019 07:29:59 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 30 Oct 2019 15:29:51 +0100
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
	aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
	linux-kernel@vger.kernel.org, mark.rutland@arm.com,
	dvyukov@google.com, christophe.leroy@c-s.fr,
	linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v10 1/5] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20191030142951.GA24958@pc636>
References: <20191029042059.28541-1-dja@axtens.net>
 <20191029042059.28541-2-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191029042059.28541-2-dja@axtens.net>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=h0t2hUb4;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::241 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hello, Daniel

>  
> @@ -1294,14 +1299,19 @@ static bool __purge_vmap_area_lazy(unsigned long start, unsigned long end)
>  	spin_lock(&free_vmap_area_lock);
>  	llist_for_each_entry_safe(va, n_va, valist, purge_list) {
>  		unsigned long nr = (va->va_end - va->va_start) >> PAGE_SHIFT;
> +		unsigned long orig_start = va->va_start;
> +		unsigned long orig_end = va->va_end;
>  
>  		/*
>  		 * Finally insert or merge lazily-freed area. It is
>  		 * detached and there is no need to "unlink" it from
>  		 * anything.
>  		 */
> -		merge_or_add_vmap_area(va,
> -			&free_vmap_area_root, &free_vmap_area_list);
> +		va = merge_or_add_vmap_area(va, &free_vmap_area_root,
> +					    &free_vmap_area_list);
> +
> +		kasan_release_vmalloc(orig_start, orig_end,
> +				      va->va_start, va->va_end);
>  
I have some questions here. I have not analyzed kasan_releace_vmalloc()
logic in detail, sorry for that if i miss something. __purge_vmap_area_lazy()
deals with big address space, so not only vmalloc addresses it frees here,
basically it can be any, starting from 1 until ULONG_MAX, whereas vmalloc
space spans from VMALLOC_START - VMALLOC_END:

1) Should it be checked that vmalloc only address is freed or you handle
it somewhere else?

if (is_vmalloc_addr(va->va_start))
    kasan_release_vmalloc(...)

2) Have you run any bencmarking just to see how much overhead it adds?
I am asking, because probably it make sense to add those figures to the
backlog(commit message). For example you can run:

<snip>
sudo ./test_vmalloc.sh performance
and
sudo ./test_vmalloc.sh sequential_test_order=1
<snip>

Thanks!

--
Vlad Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191030142951.GA24958%40pc636.
