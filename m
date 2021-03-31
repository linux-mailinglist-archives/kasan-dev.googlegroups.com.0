Return-Path: <kasan-dev+bncBAABB7MXR6BQMGQEIZT6TUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id D280F34F5C6
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 03:10:22 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id g14sf248002qtu.12
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 18:10:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617153022; cv=pass;
        d=google.com; s=arc-20160816;
        b=XmKKUPCTPCiu52wxmZ5+jhGYrkxg9kL6LfAHyO5lJAKHw2mPN9/gT3EEIn4eCRbztp
         /V+pNlT+KXfAcgUCGyuvLbxE30S+WTtbgBi7D4aDJ4uumDdIpxsbqoajzr8uenh1YDzn
         F55izOvojqPv8uo+YaMGE7sMa16wSgGUGwYCLJV1k/hwsaLwHoMUOIM6QK+kiIi9rvIu
         k9DesSSpAidwegSmes335q5wshv1Z9S3WaUEiVr+DYp/TOhE9+zobfR2yX/SUd0wNsJP
         HDEQQlYu9bTamffv/FxYOGMIwUaQ45Ldx6zgH7a5xe/jmaKpQh6/y0nODmy9Wi0VaiHH
         4eMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:date:message-id
         :subject:references:in-reply-to:cc:to:from:sender:dkim-signature;
        bh=hHOT/tesbvA64515BVzAEje74gHxqw3oDFewDhskFU4=;
        b=iCvBL6umLS+ULFNL9fXVLWOtNYiUSHyw88iPIJMWQ5RZIFyuKyTmwlcyblCl3o5WBz
         xbwMEX9Xj+q9hqhvqItqJR5xOqBmwUC33267BJovXbTVf/LmzcnMMJUipOC6IeEkqnDK
         RqTxH9Pt/PiYlJpAAdQsYzQ1Xijqj2q5aIX4oDRJ6m417Q5cLa+bWQR5JPvYeI96kzIk
         0Q0XQPebq6UhRymE7KoXm62WJN4zEWx83FrIk28HD2GohYDtfQPmd76at2dMKIO6aZef
         vZWUyHHsQL7cAvuTNwnEqKrQlTuCsuRtsfpXTZ4LuonNCU/6AVHJwHnqd4YvxbqjyuwE
         80gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of michael@ozlabs.org designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=michael@ozlabs.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:in-reply-to:references:subject:message-id:date
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hHOT/tesbvA64515BVzAEje74gHxqw3oDFewDhskFU4=;
        b=SXQ07SIoacj3dLL0AhKJcSOFluAq4YboBt8O6+q2mVfQXmLWkleD66Xe9KSnzI9loq
         WIAtV3TCayBTIjsj/Ae2/QN0skSDTVjOZEgSb2+Q4vD4LDPHTQgmY110wbPnqgy5nvGG
         rWkdfw7Uf1qAqkkLfm4WykP8OzDvBawWVTDuMVAHNiqyAjag+CaNowOTs4LzueQxyXSn
         SA17oAysZAdIlNiW1Lr94UePiUZ8fTJFFFKxNjeXPYbPWBrUOO6gF0F0tr7NKQEk+MuR
         e+EIHdJrCqLmjvrIrYtCX+TTNbjdrJoSy0cKVjmNnDHVS2HKwBvp9Dy6gusuMqYT7vPK
         qSSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:in-reply-to:references:subject
         :message-id:date:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hHOT/tesbvA64515BVzAEje74gHxqw3oDFewDhskFU4=;
        b=iG10EEKvv7lhOLMikG/6F6BymwoOx6xBY62KBhmQT0ZELzt9NTZtV7UXKEdFbX8TZs
         cLYaqrFI93OO+P3+KyUoReAZotKe3GVXbsVlITTpK666vsDTO21m5jNYUOvf+dKe7AKW
         KwvojFE+/7mse8bmld89wOd8+VxmjLWt0MUfQOCj7v9okAIdfaD3JRaDOOMVahq8eidP
         lbaUpXXy59jMpTowgnCKE2A0dBzBt7iiinhFNcNgHGpYMOinWG3SSUv8Q7LBr7DhzeOQ
         +MhLgCrI5Yb8yE135O3hblzB3mupJWCrx/YlFJahhqztuuiMfcv6YFgHGvfuQ0dNfVUd
         uTrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533BVQOtO2byTFdnipbfYe8uDec8hl/BVOy9zwzMdRe3lriKuFEt
	BplkADU8iIJuRc206nRONXI=
X-Google-Smtp-Source: ABdhPJwtt3jBNJ+ga3daaWpWctPodIe/IdB9So+OgUqQ3/XphiqDiy2YCmBGKzgn2ZjtIMVYTrx7nw==
X-Received: by 2002:ac8:7f51:: with SMTP id g17mr479870qtk.111.1617153021885;
        Tue, 30 Mar 2021 18:10:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:73cf:: with SMTP id v15ls279670qtp.0.gmail; Tue, 30 Mar
 2021 18:10:21 -0700 (PDT)
X-Received: by 2002:ac8:698c:: with SMTP id o12mr502354qtq.340.1617153021176;
        Tue, 30 Mar 2021 18:10:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617153021; cv=none;
        d=google.com; s=arc-20160816;
        b=I2t93mOPDpnESLAdLmD9x6tTtDP1OTn0rRHcNFM9EUmeLXBfdk2N6BHaW9iH8wIX5T
         RultsHMw43duDi2Aedo6vDBUIL9+X0Dug2azsIBsedlYe5dKB70EcBVwqSEBg0rdecFg
         QIDpwxNjs8Ieprk8DIjlrSlb/Mvg5AwLozJS+8YqYeV7NfEBhmkeyDIW4rRWSKgesd7z
         WcV0g9fnh7Et3sTS8wY6O9V8BPQz+w1pmbOJy8CcvmXsB0rwzlNDlJNOnseWkfRd4mNw
         Y+nmrHzZafwo0uB1NcVeNDAeTnRqtnyWAnNDVTQFTlVNpUgdY3XhilMzjnXiuRumt5E0
         dzVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:date:message-id:subject
         :references:in-reply-to:cc:to:from;
        bh=sDo0HWcJBlzweYTzf5RFxIhh9t+asJhiUoNRl495GB8=;
        b=xqfteap9iEB0hxyPGhQ+1XHt9OCfqsQV+XVgqSSf2a57R3gnxswYpo0mghkCdrpY6O
         OLFcehneVOw+WrQ0POYQ7SlWme5nfPq5BrvFg/oD39AsLlFeVwXYC/7KJFOwmcjEC+dq
         37T4BGX+s1suknoAHWWzaMsfphGl4qsb8bvmuC0JGADzwf+yPPg9zJpoZJcl6oePOI8X
         u24ntm524ZvNHLEQW0pI7Cy3Gycincjtmz62sni/vR88B0ipmr6oYy2RUftlAtvByrL6
         rrI9ZTTdPuf4EJyCOAoH8dspo2Qa6YtXMgIaB1NJ//yuDf9CWTptbJXQD37lDsUXXmAP
         s4kQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of michael@ozlabs.org designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=michael@ozlabs.org
Received: from ozlabs.org (ozlabs.org. [2401:3900:2:1::2])
        by gmr-mx.google.com with ESMTPS id a15si65904qtn.4.2021.03.30.18.10.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Mar 2021 18:10:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of michael@ozlabs.org designates 2401:3900:2:1::2 as permitted sender) client-ip=2401:3900:2:1::2;
Received: by ozlabs.org (Postfix, from userid 1034)
	id 4F97XR20Q6z9sj1; Wed, 31 Mar 2021 12:10:15 +1100 (AEDT)
From: Michael Ellerman <patch-notifications@ellerman.id.au>
To: Michael Ellerman <mpe@ellerman.id.au>, Paul Mackerras <paulus@samba.org>, Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, Benjamin Herrenschmidt <benh@kernel.crashing.org>
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
In-Reply-To: <8dfe1bd2abde26337c1d8c1ad0acfcc82185e0d5.1614868445.git.christophe.leroy@csgroup.eu>
References: <8dfe1bd2abde26337c1d8c1ad0acfcc82185e0d5.1614868445.git.christophe.leroy@csgroup.eu>
Subject: Re: [PATCH v2 1/4] powerpc: Enable KFENCE for PPC32
Message-Id: <161715296631.226945.8593352881430375558.b4-ty@ellerman.id.au>
Date: Wed, 31 Mar 2021 12:09:26 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: patch-notifications@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of michael@ozlabs.org designates 2401:3900:2:1::2 as
 permitted sender) smtp.mailfrom=michael@ozlabs.org
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

On Thu, 4 Mar 2021 14:35:09 +0000 (UTC), Christophe Leroy wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the ppc32 architecture. In particular, this implements the
> required interface in <asm/kfence.h>.
> 
> KFENCE requires that attributes for pages from its memory pool can
> individually be set. Therefore, force the Read/Write linear map to be
> mapped at page granularity.

Patch 1 applied to powerpc/next.

[1/4] powerpc: Enable KFENCE for PPC32
      https://git.kernel.org/powerpc/c/90cbac0e995dd92f7bcf82f74aa50250bf194a4a

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/161715296631.226945.8593352881430375558.b4-ty%40ellerman.id.au.
