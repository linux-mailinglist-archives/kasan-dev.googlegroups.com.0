Return-Path: <kasan-dev+bncBCA2BG6MWAHBBMMZ52IQMGQEIPL2E4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FE694E5A77
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 22:10:10 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id w17-20020a05651c103100b0024986ae896fsf1078846ljm.10
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 14:10:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648069810; cv=pass;
        d=google.com; s=arc-20160816;
        b=SBHXfAEhkUhCTkTP/I+a5AtypkwXgwnu/ddjYl+obrZPhVEcVqgUHXN38L9YgD38SG
         1smRc5ZGrMgI40mUYtcG+zTlNh2UJNdCLi5X/6EL/S9zH7SDTBBPkKB/aUpvP3iHV9xn
         RhesTBKJor1YDdTYTmXJrMrTbi0EriRktprHLmejlLXwZqyxQa2uSrH3RsBnI8/4aTcv
         CMs0DF1kCRX6B07BFN4/uMdrw/ZMuLtWPxMFbvopsDsGHPpQgcYMP5Fd30BVn3HdJ6f6
         qYstbeaK4lo14wE/Xf3CAKx/hpueC7QjzHla3I9B/EVEW3V+mA0dgsC+4U7xe37sDTUP
         0Rbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RqBslIlM+6nQJJdOYcsTQmZnNwhoa59AbpRzrA+OHOM=;
        b=Cz4bWMIj6N5NsCaZwt/+gthKZxAyFm2nkz2J1a43sPhxQNjQBQntBXFFNfTerD2R30
         it36/DBdLS5KS7987wq/RGAe0ZuXrYH7Gr+lN3ksfuwUpU24liKLZKtUW8081pLL6xg4
         +jhUqlEyuvLHIeknd9kPC7MMrhzOgmwQsmgmSrmEw2Zej6MrvgEDwBtNj+5uMhc8JnVx
         LxjtOvBfjX6vbPaRCkhKyqcVdCYX8rhavsaeGQpapyU/ZTfgCXhsEfzSGiCauFpWvUEy
         uG5q0fnjC77t68vGKAMNJo2BhtLxitUJTfUdUY80tO1JBjdvrU0b7sooo0MH1QMLR1dh
         MMtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oTaYHuj6;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RqBslIlM+6nQJJdOYcsTQmZnNwhoa59AbpRzrA+OHOM=;
        b=mrxEkC+QRXvv0Swf6+9b//lNAWkkJAUJJI4MC1t1t6SJpfsV+Q34vALq4X112/MzWv
         qfSqYDcB2xp5Hdn22RK6Zw4SsB8oseanYn96x0xhnaKgLrHrEyWgqG3IxT6ieOZ/Basa
         lCXzCjncislcfR16qLdiBb1y1qcW9u1dQEzff9LLn9Ftjdt8RUr5GIzR4V8aS9zCOEbF
         5mATBrBL2AwsAo45RvrLFcnDKrqzrTdO7XHwExFJdf/MlrCjUPAaaUPLDLeU2t88XrPf
         NHmhXA4g7HIAuefyFSEuA4DXKv7tihwkCvhKUWI+cV1ETOfgGwe3N81LD8FfBOgAc0eC
         FlVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RqBslIlM+6nQJJdOYcsTQmZnNwhoa59AbpRzrA+OHOM=;
        b=VX2WWqzrRjXBPcvlyMidfT7PFh15TMg1IWVpglHbIENC+bFGXrojYTX+TGS1Xh63UB
         AINfILWAzeTraf9KLGmwBD8E3xGfttMEMVrl3n9291k/UgiqASjnrIRiNEtBTpxJohks
         i/bD8g6HXk3go9KZ4IxnpBuKlPPe2jgyvN4KjOGn4YmtvM9ZY64RWM6l5EHMIPCpuJSE
         O2kLY/vGc25wt+62xXNv4liDNfK0kdS3XNejcz1/KDNiWXtLwuIeyF61dgtvnVlBd3my
         ITBy8S/lbWcJJTsFPwrhSTePjvdwjZkpa+nWLx3ifHYGQrKVCUeF5izbSJrkx0Uq1vMX
         N6NA==
X-Gm-Message-State: AOAM531v109MW0dFam65ObshvnP2D5OQjpVpXXxYEpA7C4fvoCS1v0TH
	iFHDFjB2ZnStZmyx6rE/SZA=
X-Google-Smtp-Source: ABdhPJy+oLfqBFl8SD9mU0JxfnV4NvAQ4CH/nIDC+4nqWOyvt2LpEkGY5RMS0F+RHbTVE9HSr19jxA==
X-Received: by 2002:a2e:594:0:b0:247:ec86:8b9b with SMTP id 142-20020a2e0594000000b00247ec868b9bmr1632019ljf.310.1648069809798;
        Wed, 23 Mar 2022 14:10:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls42712lfb.1.gmail; Wed, 23 Mar 2022
 14:10:08 -0700 (PDT)
X-Received: by 2002:a05:6512:39c1:b0:448:3d37:2cf0 with SMTP id k1-20020a05651239c100b004483d372cf0mr1262903lfu.273.1648069808802;
        Wed, 23 Mar 2022 14:10:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648069808; cv=none;
        d=google.com; s=arc-20160816;
        b=R5CEzigSXFwKpdmpFW9GBgN98il5qQ+HybxdBYp8x8y/BUKA6b9KW8pxVApVM91eFQ
         MzcVgHuEFCNsbgGxbuzSDckEqC9FRhwnRqCy3yZEfBLjOtPwwQXUQe2fq7Y1PAv2S+C/
         Yati+xynkC3sMpMnwOIOTN0RXaKQhuKSIwREYV0jyqwEFTrt1jc4jwwRMUWFNDe0aLJk
         sLtv6V34AN3aKjhmmh8N5+FaGsdbdJqqYerYdDa3LjzH6+2nAokAayoECPKBu+KTarqA
         ieLBL5u5ELneCSaEn+aLLBczxkNChYIKpk8Mu3AAx2Wun2Kf66FO+pnPZ/9e4GZX1Vbr
         wTVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZfhZGToUySyQoBAAzoaBItg7GXPjMEwgO7XHu6m15vo=;
        b=COkkqeP+Opoy/vR7jh+bmHd7euOX1dp4sPm6L2YPe45g7PnZOveQ15j68zPIMfO4lN
         DlO3AZ04hJR9/PIvxtwWYELWnIAP5V5m9Yq6mY9jzyEr8qKb0wwIctdpfGfRxO9qtf34
         LIVnQxXe6rwf+iT55HQTmR39fmxZaU84CR4RXNG8NXUVzkSKceGsuYKvvfbXNMbVpgt3
         MDN1dyUFs+0K6CN29GqVxSgSQVFu/UA6bDQjuWGNs5dGJvLrkAAPZLy/GmgrAT8gCHQp
         G+D22Cqsupa7CTQppwEaO82FNgUSP+Unt3B5kBjbJkw1PvWs6kZoDZ3mhmRhFO+C2/EZ
         fw7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oTaYHuj6;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id c11-20020a056512238b00b0044a538b0865si64190lfv.10.2022.03.23.14.10.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Mar 2022 14:10:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id j15so5341262eje.9
        for <kasan-dev@googlegroups.com>; Wed, 23 Mar 2022 14:10:08 -0700 (PDT)
X-Received: by 2002:a17:907:c018:b0:6df:e31b:d912 with SMTP id
 ss24-20020a170907c01800b006dfe31bd912mr2229796ejc.196.1648069808337; Wed, 23
 Mar 2022 14:10:08 -0700 (PDT)
MIME-Version: 1.0
References: <20220211164246.410079-1-ribalda@chromium.org> <20220211164246.410079-3-ribalda@chromium.org>
In-Reply-To: <20220211164246.410079-3-ribalda@chromium.org>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Mar 2022 17:09:57 -0400
Message-ID: <CAFd5g444yDukdiegQW-H1kV1uaRYCzoX55WHoewHx6KTOa5DEw@mail.gmail.com>
Subject: Re: [PATCH v6 3/6] thunderbolt: test: use NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, 
	Mika Westerberg <mika.westerberg@linux.intel.com>, Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=oTaYHuj6;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Fri, Feb 11, 2022 at 11:42 AM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Replace the NULL checks with the more specific and idiomatic NULL macros.
>
> Acked-by: Mika Westerberg <mika.westerberg@linux.intel.com>
> Acked-by: Daniel Latypov <dlatypov@google.com>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>

Acked-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g444yDukdiegQW-H1kV1uaRYCzoX55WHoewHx6KTOa5DEw%40mail.gmail.com.
