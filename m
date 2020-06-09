Return-Path: <kasan-dev+bncBCG6FGHT7ALRBBWE773AKGQEFZGLUQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AC3E1F470E
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 21:24:55 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id j16sf8941229wre.22
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 12:24:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591730694; cv=pass;
        d=google.com; s=arc-20160816;
        b=O5eU4K0ZNX66Z0kNhxuQmYau/ZZWTy3WPDwm2p0fCuAZNlbaCrMGKUIIbpmX+0L0da
         WWeWep4m2W8qVUXErw1r2FCK9uvmCnKI6NoXv6yNFcuvLQ7RaDgLC2rA2s7I9tcPyr5w
         HZIZ7qHt3LPuX2T3pegIYzjvTVj0W3YrPvlZS2uJFDFHYCvFhdlzGRLWHq8SL/N8TXtl
         PzKvdOUA330TCCFuPDvW0Ecw6Qg+vS7WmpxTvyadaUMsr9UZB3hMDI9/C6FHwMd+RcIx
         TFuV6Vgdqk0JSCsq2yZ2zMyTCX+V6a72vOkIogl2uRpIMmHeJZ/acFLeVwm8qnn1SYTd
         a9nQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=RrD92y6XW6BeCATzJTSvDEtE1CbwGfoj/7ujOfrSP4M=;
        b=hcNLCjvp0YcJPkNjrs2+QcXtdy1WyGA9rhywFGm1JIQqK7xV2if8V7QPwdaqP3ZEnY
         U6vyYEunyliecEu3wT9f7VqemFATVQ1YQjOO0adYyfhHrc6hQTQdkgbFrAqrTVbtSw+G
         WI7b0zLrVbHNmMpBrQPECjtJ/9COKlcgTQWIYqFE0d/rat+28rc6SL3gUn8FzaH/JOr0
         mEzblVuf+HgtiFlUFWGchEnwhOkuDT5QhiP2MoEDTYptmTI796gDV57uZFSgZ15CBZ/P
         nG0syYs5h2Ph+5+g8/RwAyWSo3nmFCNY9WxIh4YymeVk8oSSKhoqXgq9Pxehak2BmACT
         cx/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RrD92y6XW6BeCATzJTSvDEtE1CbwGfoj/7ujOfrSP4M=;
        b=UV/zJr506pV4FRKZ5z2GinLKo4Koa4ocIEiIz9V/t6XlrbJHHVadAdKMEVHx0Vr4DF
         qso2TiCC5k6MS9zPkckYP3gPxfVPZqkfyXwBZjfUoeCbQ4kY+AHlMRhD0xah9rgWS2mo
         uxg0gUnYZ9guq6ptCBk3cJ+254F9SIAQxiXWaAXsojvpct6xhjWIYKxDGx8IhhH6z8IJ
         b+SZ1xf8nMIawT22mLCW/NRCJZSlkrV8DMWZ1Pd8IZ92Ja54D3VADFzanpfEL8ofp67E
         GhOR+ZgUv9udu0zlvOrE858fggKuSniHKK0IA51OYZ7JqrX6UpTdlUEwCcKRwpOg1xjN
         osGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RrD92y6XW6BeCATzJTSvDEtE1CbwGfoj/7ujOfrSP4M=;
        b=PDQDkOX/LMqFPIMEgc+a0yIIfiEQOFJVaFNntBCNGWfQBozBcdRKcBTtDdIIjm5byo
         V8raNGrWcpKRR98ytqToT3hfIKPNaB62a7HnPc57ZMCOZjGnHsQv08FZgNXOZoVl+I6G
         RFApURi8HGiZ/9L1LZGus0t4czu5n+l3D1NB67+wPr5WhlHmQvgAWTzb84J+rewNEpei
         Mq9h5k4uV7zxZCrXm+e7Z6AvJV22EjBf7e0FrB8gq9cAh+YeBJslVWSk01a9q4gY+S9w
         0T8WkluGZcyn7rtRBJ0eUn92Fnh+ofY77RBebiIyixNW0STbGH4HUBB6s8/tjtgFp4cL
         ThIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530sBSd/cOor48U+MgfmkjUxGfDnjtCyBwBOex5+/HVjn6WuP/Ax
	reD3KHLRS7dMErOwbWabFjw=
X-Google-Smtp-Source: ABdhPJxSuH6J1pawXBg9wFJVWztc9v5Cljgf8o7+pZDYY3tTovtV+xeevoHk9BTQEmUaok9GcsZjJg==
X-Received: by 2002:a7b:cb93:: with SMTP id m19mr5683571wmi.165.1591730694838;
        Tue, 09 Jun 2020 12:24:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a545:: with SMTP id o66ls71504wme.2.canary-gmail; Tue,
 09 Jun 2020 12:24:54 -0700 (PDT)
X-Received: by 2002:a1c:2082:: with SMTP id g124mr5702071wmg.21.1591730694304;
        Tue, 09 Jun 2020 12:24:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591730694; cv=none;
        d=google.com; s=arc-20160816;
        b=NUZrYNojHg66DA1imGgq6gUyPSrVCHC1sqLA6RPxJDBpnzvWxxXSwt4Fd1V1oxbmmq
         YDWX7/KfmiW0H6u9pBO6g7BDs2WalhHml3FwIvFJ5U+hcBdaAQEgGTo7i1E675pX2A2J
         maiYyNCZwOhxj3hr8UAIp0qQRHdld5TUyvqpZBbphKdGCqvuCRABSQO0+SwJ7Cm/bq+v
         cvnmqWTHWBqgsAErKsLlYStFfwRtJ81s5iOyBKjgMBhF8tEVCnsLP6/CKVBRrDePYAJj
         T/srBy3tF+HpOGhaHvOkDahHUVj+ex7iTTC3yjVZgG3MJi549dtIPZwgRcinQDvKdra+
         9UxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=/Due3CzvXX/U5Q/e7ckTjzhj+jnHJatcFAlz4bO37Ik=;
        b=pGe4YxhzuZcozL9B76yn7ikypd8+pABj92tT0ehhviBjbOgBAOMyZnqOarBKYvXtp/
         erOQ3J3P2aNFhiajZk24ptNn+dHUPPlTr3t6ZeKKbbvUzpaIBSxxTg892EYyFFoEkUU6
         nCjYPejrn0a7n+WThZ9A2mkv82qvbswPI/tyWSNHetY1fOCM8KGehS+Q0ZFsjgiClVr5
         gsuh9KZ2IJ4hNd8i9yRpAtIscwx78GN8MYzrYnlrRo6amfezNEr0p5Fi+hb/ZQzoyl9K
         brin3X2hYiXbOs+8n7yBAtRE2i3foHiJRsLgDHwmykkPvStKOOgc6hFIPjN/P+n+iPsK
         wbFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id z18si214487wml.2.2020.06.09.12.24.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Jun 2020 12:24:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 57947AFCC;
	Tue,  9 Jun 2020 19:24:57 +0000 (UTC)
Subject: Re: [PATCH v3] tsan: Add optional support for distinguishing
 volatiles
To: Marco Elver <elver@google.com>, Jakub Jelinek <jakub@redhat.com>
Cc: GCC Patches <gcc-patches@gcc.gnu.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>,
 Borislav Petkov <bp@alien8.de>
References: <20200609131539.180522-1-elver@google.com>
 <20200609132216.GE8462@tucnak>
 <CANpmjNMhKeg2KkY9K-8W_iwsvZgf3_s9rWOcU6nE=Un9_uVewQ@mail.gmail.com>
From: =?UTF-8?Q?Martin_Li=c5=a1ka?= <mliska@suse.cz>
Message-ID: <8837bb2b-cfc5-77db-57ea-fd8b777f616b@suse.cz>
Date: Tue, 9 Jun 2020 21:24:52 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNMhKeg2KkY9K-8W_iwsvZgf3_s9rWOcU6nE=Un9_uVewQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: mliska@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=mliska@suse.cz
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

On 6/9/20 3:47 PM, Marco Elver wrote:
> I think one of you has to commit the patch, as we don't have access to
> the GCC git repository.

I've just done that.
I also fixed few wrong formatting issues, next time please use ./contrib/check_GNU_style.py.

You'll be preparing one another patch, please request a write access:
https://sourceware.org/cgi-bin/pdw/ps_form.cgi

Thanks,
Martin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8837bb2b-cfc5-77db-57ea-fd8b777f616b%40suse.cz.
