Return-Path: <kasan-dev+bncBCT4XGV33UIBBMFEQ6SQMGQEV4QPA3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 36CDA74506E
	for <lists+kasan-dev@lfdr.de>; Sun,  2 Jul 2023 21:38:26 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-7656c94fc4esf443707285a.2
        for <lists+kasan-dev@lfdr.de>; Sun, 02 Jul 2023 12:38:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688326705; cv=pass;
        d=google.com; s=arc-20160816;
        b=MCQ7dhaE4MC4SlKy0VUIPVXXHp2Zpzq+zBfuC+A2t9JNlQDj/zk62giTwXGaIPz0x2
         LPXrS2mxqa92WrDU2GCqf/nqqUxEvLeUedPKr9i0BmYeA9Zhc5M1e9P1DOgoUFJYxXEA
         vSHWhO/ZGzaBmxAjCiJgU61bEEjIVYqAjpuVsO8aEw6g5DjDcA99svwfLJRbrnfhIOAf
         xlPLXsf8GucthlLazfOkuQlPMCeY3oxImytGVMRCxYZE+v4rPXCuraM5o9hP0tuGtr+f
         VaCFhKuoJUJzirPwqY80M63oWcrW3kmtscjyciTtLERGOupDRZQFi6dnI1JDgRyLKQOu
         EpYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=gEdVps7tmq0DwN1Nj6k188CdH8zYxWtH+T312Op7218=;
        fh=SqbZ8PZvb6XNRZC4vf5U5q9M+mc1vP5cUGAmSYZ2GFc=;
        b=PwmlIC1KiGa1BIe8v8YgAwgaqxHz80mGHvzW2KohIKzv/4P0FfMnS+WLxmmYKc0w4M
         50BkzAaI487GBbanrpaHgY1D0prPyZ31W2JDUEoZn9DtP0JrTCb+MeaJHiT9ROnqpMsO
         qRNnvdWbXtY+TftI5Xes07e1D571BzIxylfzEKlxdASL9E0yyMGkJ7cDWhnsBwP+cX6Q
         fFkF8AaOYPOvDna1xuyTr3WFJXM+bVFJbGTyqz7eBBeg/tVPUzMp0g3Q8ioVbmKdoeoz
         +/ho33Ma/fePIuFjh745C08615rAUyq+DOSe4xgB4i3eepzcGS5b61RGjdHBRpQFxpSs
         zIsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=w6JHpPK9;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688326705; x=1690918705;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gEdVps7tmq0DwN1Nj6k188CdH8zYxWtH+T312Op7218=;
        b=FQEmFxVsNXjDJT17hoJrQEQznLJ3r51A1z3qIdz1gE+F0m3dY7zPsLLGVC90jFtwMc
         pZWmfGLZTNJK6fUFFGLXJDUJJDUk8XX7S7TmqFbockWMI7p781WywJ7vYzM1evWIEkBH
         VSfVn9ZwGQS62CpZp/OjCidRiDvl2BjvS8NfzYYDecVB2p0bmPUL9WXN+KYkI4W40ws6
         Q80acqXXAgzFlAuThQUQkwRWZXspnN8z3BQr7oSmNFC1Sj2nV9l7xq23axxizIkHotok
         EnyP+aFMadcNPfap9UTPjTptghom4mQZvjuhpm4tP7KDD+rx8/L9LzFWm2ELh+WTg6W0
         QVtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688326705; x=1690918705;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gEdVps7tmq0DwN1Nj6k188CdH8zYxWtH+T312Op7218=;
        b=IbO4G/poLI+L72Un/CmdakrYk3fgjv1ftwTrJAxmJv+EVBcFY6Yk5zwyrb9nhDYS6m
         tuQhNgk0RJXriPml0zbrHuS0ykO+ttAiADQx4BRrPKagGPpAPHMg3Puchu69Tzff9L4k
         OnZMqmQ/eQ/Yi7oG45cXdNdLo+rFFyBII8NvtryX7axzURFwQQG1aHGCzgod8YDnLgVd
         cc52au9/uIUILfia6LGTfV2vmtap9vI+6S6LTostVdNDTEOESUk6kuTMrsw2kRbJj+mZ
         btG2qhaETPFgWkZWuT+w7Aw7zgI+7CJ3z7A0m7LmQNvxl2Bg1Ec+rhpFwQGryqsDeZEU
         1IRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzBalil8Z+02OxL2kIrvL/puFyWA8HvmWsVc31tsFmAGTzh1G8J
	ZDv/uu5qIbMbB1YMxfj6nm4=
X-Google-Smtp-Source: ACHHUZ7kYMPiobT8O7+k3tCwAxElFY5a2IllPDKSZ0+P/NjiYFkVmy2mmJ9JNBiBSsDRxLaRkmkOdQ==
X-Received: by 2002:a05:620a:2807:b0:765:9f15:c324 with SMTP id f7-20020a05620a280700b007659f15c324mr8161320qkp.48.1688326704818;
        Sun, 02 Jul 2023 12:38:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f841:0:b0:635:f50d:1c05 with SMTP id g1-20020a0cf841000000b00635f50d1c05ls4596571qvo.0.-pod-prod-06-us;
 Sun, 02 Jul 2023 12:38:24 -0700 (PDT)
X-Received: by 2002:a05:6214:258b:b0:625:7c0b:4640 with SMTP id fq11-20020a056214258b00b006257c0b4640mr13034918qvb.22.1688326704223;
        Sun, 02 Jul 2023 12:38:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688326704; cv=none;
        d=google.com; s=arc-20160816;
        b=AFEplFx/qMUKma+iXAe6Wj77lFj7FhGo298W7AbBI/OlqzRO9L58SB212LeBZj2STS
         UvTJ8k62YffVIot6USXR5G9nLYjdmerPxK2bdv0tfivfyJbK2ykqrpgFAH1FmS4RQcz1
         /jlGZ+XKCCYmyyTUGhVmeidvTc1osMBUbxiV/b4x1z6Gnlysis3LbK/I/qsBSihjW5zw
         4JclJduVJp2DFD8HhEs954sOIj7S80FGYkoq6s1Hh27H2KComsK81YxgwqRS7OzjC839
         xOvytZgmvDysSnmToKSnBFA0CusRoV3gEHwsVzUoHHDBgDU/ntMYEGOTVKa/B+5cB+RY
         w3SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=rxLquEeFPKTQo3s8vItwsyTp5qcOPEMlU3lkjxVwO8g=;
        fh=6Ls2QgFcm9adOTBIA28Jl2I5Qpo/rMsrFS547z2ir1k=;
        b=RDiXFtY9+xd9LFSMOhQtU3LeyMWcghEJDxYejjm3Okde/g8dOLu+8tnKjv7YFc/7cW
         f+iaQMdIgYEpGChnk5DYlnjiWA2GSOKZRhd52ZY+bpL+HNe1ZxodON0guSnwd2pFkn2Y
         j049/heoL5Wn9erQO56a1YOKLF7VPZ0tJsnRK/uKYo1Q4LGP/7eEENeq9Y8yzEipUkqz
         y/0mhHTHKZK7e39f3it7lJkBOnRUDeJWUvjpATVfpRN7ePQ1tBWHhd0g8NIX37ugLztC
         rb/hGmLJOOEGWOUg6fqS8Fy4yWvP5Eu6N8pnqbj6Kljy1U2lhuya4d6fQ6Cc6nifkELI
         Xsqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=w6JHpPK9;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id t7-20020a056214118700b006363f2c380bsi473943qvv.7.2023.07.02.12.38.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 02 Jul 2023 12:38:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id BBCE760C8E;
	Sun,  2 Jul 2023 19:38:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 70EA7C433C8;
	Sun,  2 Jul 2023 19:38:22 +0000 (UTC)
Date: Sun, 2 Jul 2023 12:38:21 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, Will Deacon <will@kernel.org>,
 Qun-wei Lin (=?UTF-8?Q?=E6=9E=97=E7=BE=A4=E5=B4=B4?=)
 <Qun-wei.Lin@mediatek.com>, linux-arm-kernel@lists.infradead.org,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, "surenb@google.com"
 <surenb@google.com>, "david@redhat.com" <david@redhat.com>, Chinwen Chang
 (=?UTF-8?Q?=E5=BC=B5=E9=8C=A6=E6=96=87?=) <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Kuan-Ying Lee (
 =?UTF-8?Q?=E6=9D=8E=E5=86=A0=E7=A9=8E?=) <Kuan-Ying.Lee@mediatek.com>,
 Casper Li (=?UTF-8?Q?=E6=9D=8E=E4=B8=AD=E6=A6=AE?=)
 <casper.li@mediatek.com>, "gregkh@linuxfoundation.org"
 <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, Alexandru Elisei
 <alexandru.elisei@arm.com>, eugenis@google.com, Steven Price
 <steven.price@arm.com>, stable@vger.kernel.org
Subject: Re: [PATCH v4 1/3] mm: Call arch_swap_restore() from do_swap_page()
Message-Id: <20230702123821.04e64ea2c04dd0fdc947bda3@linux-foundation.org>
In-Reply-To: <ZJ1VersqnJcMXMyi@arm.com>
References: <20230523004312.1807357-1-pcc@google.com>
	<20230523004312.1807357-2-pcc@google.com>
	<20230605140554.GC21212@willie-the-truck>
	<CAMn1gO4k=rg96GVsPW6Aaz12c7hS0TYcgVR7y38x7pUsbfwg5A@mail.gmail.com>
	<ZJ1VersqnJcMXMyi@arm.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=w6JHpPK9;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 29 Jun 2023 10:57:14 +0100 Catalin Marinas <catalin.marinas@arm.com> wrote:

> Andrew, what's your preference for this series? I'd like at least the
> first patch to go into 6.5 as a fix. The second patch seems to be fairly
> low risk and I'm happy for the third arm64 patch/cleanup to go in
> 6.5-rc1 (but it depends on the second patch). If you prefer, I can pick
> them up and send a pull request to Linus next week before -rc1.
> Otherwise you (or I) can queue the first patch and leave the other two
> for 6.6.

Thanks.  I queued [1/3] for 6.5-rcX with a cc:stable.  And I queued
[2/3] and [3/3] for 6.6-rc1.

If you wish to grab any/all of these then please do so - Stephen
will tell us of the duplicate and I'll drop the mm-git copy.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230702123821.04e64ea2c04dd0fdc947bda3%40linux-foundation.org.
