Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB7NCX7YQKGQEANO5RPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B68914AF9F
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 07:15:26 +0100 (CET)
Received: by mail-ua1-x938.google.com with SMTP id 35sf1301084uaq.20
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2020 22:15:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580192125; cv=pass;
        d=google.com; s=arc-20160816;
        b=YyNzF0w3NCwRA8dDcNg765D5AXoor0CCWy3qptCwLGLuL4icXcCkoWAKHNPjOLVbrV
         K5uH0q0k0wXbknqskQL7uXyrdf/lfPUOCiI2PfyLDnd4vhV7QL4Ooere6oDM3SJcSqbg
         B1p8y43S+1XDbfKhBKp8mCWDlNzSGbdNtFv8ZIS6wYCBX/MXpqr3bcF6U4EcwQjN698K
         thtHRSCiEzG99BPdd0gRvi8Un+TP+FFzXB0RrbEO0UzwmYTsJwr8MJo8Be1R5Jtm/gEd
         pKn31eT5KVkLmr1xJnJJgqyyz/sHTixBYDPex2EvdRNmXoFBb1iq+edxJmGh99KnN3++
         3mZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=KFTwq8IxJAiQbCkeZQiguOwmB/IP+Lm1JoNPLeupHa8=;
        b=JvPOyZc1RhRui0GR/DGGZbun57zWHtCV1SYRFjWXR+sYEwVdI+fG10Ez50/v1tB2fg
         6LyhMc1XhUlHp4ZMnXh1dDqRtNktnnmCa6blNZkv7uyj5PIAKh2RN1LdfaaGXInseyQ5
         Fmu+qUjY9qFhhJHTWuMH++uFlnhVA7t5qMrqZA+stD4SPwTC0CbpVgAsQki9N+qccTAL
         IY8LjazSIGmv0iewQ8ar6kWEF/P6PRR5rX8cl7tuAs7gvMMkSbRHtqf4OYlZCMsBta5d
         ypE/2oh7lENFdNgyYMsciuRyJmQqIvyNqurRevWnZmQWdw1f0xTL3EfXk0LwCPCwxcx5
         O2mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=VKXqwFjm;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KFTwq8IxJAiQbCkeZQiguOwmB/IP+Lm1JoNPLeupHa8=;
        b=CK4s45wC61E2MJCLeTbfa1Jgdw9O1RJVD71IWi4oksBtw5Dsbd+u6EL2NwGLud7TWr
         a9VRM89nWd2Si8wpxJmr+7FYp6LqNxDi4mHY38CoWclceCeLQTuLMy6XH5zI4OKVAG4d
         Gkyemt9GnQBKsjniYSnWZ4SkwIfKLPs2hII5v0Ia89hZCGjPjsIJJL18GE+0JMmUstVA
         jamK3ulGrfmknGK1yOuvLa0DUpUzyNDUgp6/FL/P8QeoVTJYuReW+03MXnn80Ndf8moq
         +mpge4VlbxZU9vqIzyHpR5FYRaSiAiHwdCphhFuh3Adc4oN45d7s/00Ve+f4Dlnp9QS6
         ATfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KFTwq8IxJAiQbCkeZQiguOwmB/IP+Lm1JoNPLeupHa8=;
        b=CS1Bwviez/soj3o2nDHc+28oQEFIkvOrMh6O4aTICyn/HOppm/lMsXqf5XpHSDoaJy
         HdVo/01F1OVdlC0ihlFj+dggJT44Dpo29madhe8ESkrCh8NOlG2/Gnq1KRqXH6nMh9iR
         US+6McG2KFOM75t1rV0Vt7GvLJU86O4POyXX6+6NWnGkSX3iXiu8ytN0qd9DgjghgruO
         3v8fVFExPkvMKSaPx8nUfrH6FFQQlhU9rm4P46zQa1au6OLn33wOk3vqnqX7JQakcVRe
         cAueFpTah3+1dl8wT0E82yNmKdaYu8XudqE2NWK4PWuMFR2EiiVbFO5GwXjJEzs9ulAE
         q2Lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWYT+GM3+B4yd78i5wMWsee3RDnOqY+SVuoGLXdBH5uqQDXn9De
	n4/pHrZdVLT04AtV+MFTMLQ=
X-Google-Smtp-Source: APXvYqwJWf48CErfkEOVb6AVycGw318jDa6PEA+tB6EbvxsXCv8EnR5fj3S4eecq6I42hPhkyR9pEw==
X-Received: by 2002:a67:ad0c:: with SMTP id t12mr12543483vsl.232.1580192125245;
        Mon, 27 Jan 2020 22:15:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2883:: with SMTP id d3ls811312uad.6.gmail; Mon, 27 Jan
 2020 22:15:24 -0800 (PST)
X-Received: by 2002:ab0:6029:: with SMTP id n9mr12393420ual.35.1580192124794;
        Mon, 27 Jan 2020 22:15:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580192124; cv=none;
        d=google.com; s=arc-20160816;
        b=XsPoUIUR76P5COo9KtD6ShL3sz4CfSmNQKpJRlGHPKZ55N3Rn2C+c0i4q2r6QvyCYc
         +Y0EtOFDNorjvsCTViFUZAJ26DNQJz1N3evzQmq16BIvpLkd3VHqhfR1V3w6Oi/atidQ
         7MMlp9bfsFOmbxZJ7eYdvrTf7uRNDfAjrwbQArevd1JxD89LjdrcCTXvtbwe3611b/Fw
         CzRx/Vj9eAcQCoFDgDFaLlFbccP7aKzzU0gEe8berYEydgxrlOQlO5tropKD/r+tIqmK
         yzyemp9kCMuMZaXWRGRrQ7DcZveLSfCSoPIEA/0VsGsw3BnMsTdhwJN8Iqqw/nJhCXw7
         7pZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=IX6vC1lqC7B6QSvzPSA4RSu0dRAbEMHe13lqUpG29i8=;
        b=KvDl8McRiyd0RNXpn7+X2DP65d6iiAuvQy7tQMyKmz9QoxXdo1Se1yH0IHnqEkM0e8
         oL55tFp4qM9XfEHeO6d9/uSXqNHqNG5kR69+AG1fBiJvKEF/KhAlzMU6/oLMcpyskgMo
         njB9ZbgWQMoYMR8q/i+91YOIhUXJyMvIpQvKDPlxHfg5VlrGEs03/g/qBWaIiY0jP/XK
         Du9nE+gGyg+LFx4/9hyoYIQEayjpFDSptrCGgCCRlJ5C6FWRlTukhMasbLLzeL6AlKdy
         5dyE4xNHf4WfEmH/hv/nG2cbJhkmVlzuC4q2IBsA4EI5jw5A4h72O6P9RRq3+2ZWjdca
         gjnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=VKXqwFjm;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id x127si809346vkc.0.2020.01.27.22.15.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Jan 2020 22:15:24 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id s187so12277445qke.8
        for <kasan-dev@googlegroups.com>; Mon, 27 Jan 2020 22:15:24 -0800 (PST)
X-Received: by 2002:a37:814:: with SMTP id 20mr20434739qki.314.1580192124338;
        Mon, 27 Jan 2020 22:15:24 -0800 (PST)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id e16sm11951755qtc.85.2020.01.27.22.15.23
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Jan 2020 22:15:23 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: mmotm 2020-01-23-21-12 uploaded (efi)
Date: Tue, 28 Jan 2020 01:15:22 -0500
Message-Id: <E600649B-A8CA-48D3-AD86-A2BAAE0BCA25@lca.pw>
References: <CAKv+Gu8ZcO3jRMuMJL_eTmWtuzJ+=qEA9muuN5DpdpikFLwamg@mail.gmail.com>
Cc: Randy Dunlap <rdunlap@infradead.org>,
 Andrew Morton <akpm@linux-foundation.org>, Mark Brown <broonie@kernel.org>,
 linux-fsdevel@vger.kernel.org,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Linux-MM <linux-mm@kvack.org>,
 Linux-Next Mailing List <linux-next@vger.kernel.org>, mhocko@suse.cz,
 mm-commits@vger.kernel.org, Stephen Rothwell <sfr@canb.auug.org.au>,
 Ard Biesheuvel <ardb@kernel.org>, linux-efi <linux-efi@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <CAKv+Gu8ZcO3jRMuMJL_eTmWtuzJ+=qEA9muuN5DpdpikFLwamg@mail.gmail.com>
To: Ard Biesheuvel <ard.biesheuvel@linaro.org>
X-Mailer: iPhone Mail (17C54)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=VKXqwFjm;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Jan 25, 2020, at 2:06 AM, Ard Biesheuvel <ard.biesheuvel@linaro.org> wrote:
> 
> Should be fixed by
> 
> https://lore.kernel.org/linux-efi/20200121093912.5246-1-ardb@kernel.org/

Cc kasan-devel@

If everyone has to disable KASAN for the whole subdirectories like this, I am worried about we are losing testing coverage fairly quickly. Is there a bug in compiler?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/E600649B-A8CA-48D3-AD86-A2BAAE0BCA25%40lca.pw.
