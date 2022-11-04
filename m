Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBVNVSWNQMGQE6A7Y44A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 01388619FF9
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 19:32:55 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id z15-20020a170903018f00b0018862d520fbsf2323332plg.11
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Nov 2022 11:32:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667586773; cv=pass;
        d=google.com; s=arc-20160816;
        b=WnuKJWOq2P6ayBBDKtqoVgjnBMqkF0UzP+K9jRSGPw6WxHlj+r33uttIUtsWTukIv0
         dGbWLI5RcAmQ28fKDMtW6P1Uy+YDm6GvvHP474lf27PPDCsQJ/FPYMSG3y/wm9d1F7rq
         8z1C6kqaRYZVyX/ld7wL7B5DaPEoSq8tqfiuTBuYt2PV1p2q6HGzeoQW60XfmJVBr56n
         D7+JXafCGpVz9arqB+ap3YDvzxmOCQqx45qJ85G35PZoCxKfOQR9Mr2dj301XV/lPCoQ
         YficKDnli/FF7AXhLozGHfZ14O31u25/Fttwtvlc6jRJ/eHZo9caZG25WltYeI7Al22p
         lqkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :mime-version:date:reply-to:dkim-signature;
        bh=kZLw74V/UWh+8UYQntRDF0bQXt0CNFKk5rNgt+MNRtg=;
        b=pmYObKRuQSdskGsXxnjtSj+J8OCav6VVmS2tbZWvHQqlESEgW6gmkxA94wLAaKxvgM
         rr57t3t3w0QOsF5fy5U6Ze0q8bnocUs5ObaZIMRwMRSBR1jKyX0jLzKUfVGjPPOulq6W
         K3C6uLOq+wJnLnj+EAdo4RPRnzZcr5y6UHPQMNfoTMwRIcqPLqRnZLTb1q1ok7AnHLor
         nlcp1DEwVrBW9FfzTo/B5fkKTiYtWowNHf5lJP9ZzrDHcN6wzAVmiHqZJKOB7NNlaZw+
         WfJfGLNDMMOd2IHZm2uSarMYDPorHWL08NIv5OBvV7CudbaD+zsk0g2EO3GJeqfwp7R8
         NLwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=o6dvlt8i;
       spf=pass (google.com: domain of 31fplywykcuevhdqmfjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=31FplYwYKCUEvhdqmfjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:mime-version:date
         :reply-to:from:to:cc:subject:date:message-id:reply-to;
        bh=kZLw74V/UWh+8UYQntRDF0bQXt0CNFKk5rNgt+MNRtg=;
        b=tgiWDUwq1q2amH6AzPrGudQ76CoKQ+ROyeF+pZrrUr2cXIROzzFUpT67eGFxc8E8X8
         qSBZHEum1uOj5KkOwSaloDGxN1vFToaHoCiMQu7FSSIw2jZzFNtEVnQr27LGICF0yxr4
         n9ETTam/qHS021lXJaqFtWbIXO+xhuSNTyJHe/Xb5TlxpAOnwiyq09+rzCdy7r18vRW/
         ABCymVCRWiDX0taWxkxKRi72jhFAr4YftZm9xMLe4CfLMvgqTnfujWFwx8T/Tjzkd8oZ
         Fxq6i0gFe60jchQn1xvF+LYPQKEGs7Js0LAoJ2WIlTUOJjY0PtYotBGGmTh1QAKuFz/n
         Kzlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:reply-to:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kZLw74V/UWh+8UYQntRDF0bQXt0CNFKk5rNgt+MNRtg=;
        b=JecPauY3KJOV67zuB3tJWpJ6L3CSwwdqLfpx+0+VqnQ2OmLMDY8cDq4OjLZski7Edr
         fJxeepDKs78nv4b3uGchZwJflcbg5LoVT+eLZdNag2l7qTq4bSeM140HtTndGaZ6/qHh
         16BJP19RdfCoz+Wgc1ChqNAR0Nbg6sivlcHV/04O1T0lERBilfTIrZxh62BUpQrdpeUp
         eAnOvLB5p1IqeAjVs+H39xmk+R7mzsxhcrayzAMC+AmfJfwhq8ULE4jVhM6HvbSHUpJP
         497fjjo1ZBRtFTez69LaSFI7pUVuE+O6bP9fR9GbJ07Rdc5b5tPxuZKCUqQ4UO7tvfNU
         PbTA==
X-Gm-Message-State: ACrzQf0qZdN6RGtgAis4yQMshfEX3rfwR1a59XNVx8m4zzGptlhO+MW8
	9OOx38Nf3qdK4xoGpyLk+Ns=
X-Google-Smtp-Source: AMsMyM5IdNcM/2M2gRdke7/YhTHgO+JUvYLbn8vDZibcVV0fkVPSWTXqk9sGeFWCFEPloJGrNAl1vg==
X-Received: by 2002:a05:6a00:23c9:b0:56c:9f62:3369 with SMTP id g9-20020a056a0023c900b0056c9f623369mr36172214pfc.22.1667586773373;
        Fri, 04 Nov 2022 11:32:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:483:0:b0:56b:ff73:9863 with SMTP id 125-20020a620483000000b0056bff739863ls2635769pfe.5.-pod-prod-gmail;
 Fri, 04 Nov 2022 11:32:52 -0700 (PDT)
X-Received: by 2002:a05:6a00:1582:b0:56d:4bc6:68c7 with SMTP id u2-20020a056a00158200b0056d4bc668c7mr30460413pfk.31.1667586772608;
        Fri, 04 Nov 2022 11:32:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667586772; cv=none;
        d=google.com; s=arc-20160816;
        b=bz7sk8BJadS2K7952ePsQa2pWDXhdpq1RQ8d8UlK4FGwtWFT7FTgGRXzIe0xflbOI6
         PZxj64e9iCaoBEgur7qOKCFlpHifskGM41XxOl1SiQxMLzCGFh4e4N3zFide1QuVDA1y
         kPEGqDSKsLVaerPO8jGyU4oDcib3r5+ynG/cVvbuBPyCEIK+tu+tmQYAXJ1+m8w2D5+k
         ebzK54i8ezrj63R8qdF/DNkPaue4Xf0BdBjVnuInCOW6m+Ul5ix6bIXHNPehxLE8FcvP
         hMWIllqxTErSCsMqkn+NenMtgCOPT9R2ElKilIUzIS0ujwuSNQkTRXnipRdh9vxxZFH5
         Xhfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:reply-to
         :dkim-signature;
        bh=HaGpOzKbqb+MuEAD+NCm71AWMMP+r3ojA1jZHAjkZAM=;
        b=n9khfHBcGd1NTVcgDgtmbRAKokOcxQugw8W5HX2a+N+CAMALwZUjDk5ftQzcn0ynoM
         yRcyrzlyEp9BZnswNZeF0+oyAVA8U5Q7KYP0XpRgTt30TD18FBmfzEdlAzOUNd4wYDs1
         ZUuyihC13zryOhFkA/m8Py6raZQzzY+ehscQ9KtxKTiHFhzLUt3rf5PxTh49lNjPgggj
         4Xowx745gXaxmLoujKQgG9PHU5qs8Xe8wst9CUEcb7P+ZS8xTifRgHFl4khVE6riKJW6
         cTTaiJNVfKJUkfCkvrITH3GkpEOCpiHJMd0HczvrYYugC3xPKcRxcpn0gqccIG+PAJE3
         5U1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=o6dvlt8i;
       spf=pass (google.com: domain of 31fplywykcuevhdqmfjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=31FplYwYKCUEvhdqmfjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc49.google.com (mail-oo1-xc49.google.com. [2607:f8b0:4864:20::c49])
        by gmr-mx.google.com with ESMTPS id f6-20020a170902ce8600b00186a2f98b30si9160plg.12.2022.11.04.11.32.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Nov 2022 11:32:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31fplywykcuevhdqmfjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) client-ip=2607:f8b0:4864:20::c49;
Received: by mail-oo1-xc49.google.com with SMTP id t9-20020a4a6049000000b00496bbda4343so1278812oof.22
        for <kasan-dev@googlegroups.com>; Fri, 04 Nov 2022 11:32:52 -0700 (PDT)
X-Received: from zagreus.c.googlers.com ([fda3:e722:ac3:cc00:7f:e700:c0a8:5c37])
 (user=seanjc job=sendgmr) by 2002:a54:4388:0:b0:35a:3a9a:cf1 with SMTP id
 u8-20020a544388000000b0035a3a9a0cf1mr8905979oiv.158.1667586772072; Fri, 04
 Nov 2022 11:32:52 -0700 (PDT)
Reply-To: Sean Christopherson <seanjc@google.com>
Date: Fri,  4 Nov 2022 18:32:44 +0000
Mime-Version: 1.0
X-Mailer: git-send-email 2.38.1.431.g37b22c650d-goog
Message-ID: <20221104183247.834988-1-seanjc@google.com>
Subject: [PATCH 0/3] x86/kasan: Populate shadow for read-only IDT mapping
From: "'Sean Christopherson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Sean Christopherson <seanjc@google.com>, syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: seanjc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=o6dvlt8i;       spf=pass
 (google.com: domain of 31fplywykcuevhdqmfjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--seanjc.bounces.google.com
 designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=31FplYwYKCUEvhdqmfjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Sean Christopherson <seanjc@google.com>
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

Fix a regression introduced by mapping shadows for the per-cpu portions of
the CPU entry area on-demand.  The read-only IDT mapping is also shoved
into the CPU entry area, but since it's shared, no CPU creates a shadow
for it.  KVM on Intel does an IDT lookup in software when handling host
IRQs that arrived in the guest, which results in KASAN dereferencing an
unmapped shadow.

The first two patches are cleanups to make the fix (and code in general)
less ugly.

Side topic, KASAN should really decide whether it wants to use "void *"
or "unsigned long", e.g. kasan_populate_shadow() takes "unsigned long" but
kasan_populate_early_shadow() takes "void *".  And the amount of casting
throughout the code is bonkers.

Sean Christopherson (3):
  x86/kasan: Rename local CPU_ENTRY_AREA variables to shorten names
  x86/kasan: Add helpers to align shadow addresses up and down
  x86/kasan: Populate shadow for shared chunk of the CPU entry area

 arch/x86/mm/kasan_init_64.c | 50 ++++++++++++++++++++++++-------------
 1 file changed, 32 insertions(+), 18 deletions(-)


base-commit: 3301badde43dee7c2a013fbd6479c258366519da
-- 
2.38.1.431.g37b22c650d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221104183247.834988-1-seanjc%40google.com.
