Return-Path: <kasan-dev+bncBCAIHYNQQ4IRB66AWWNQMGQESFSBMFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B9088624BEA
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 21:35:08 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id mi12-20020a056214558c00b004bb63393567sf2334604qvb.21
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 12:35:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668112507; cv=pass;
        d=google.com; s=arc-20160816;
        b=o7x+7yGS5HoDYUDRoHrUQexYNRJq7WGaGO7EqZoPo+6LgP9vCKMxqaGGxX9Teap4et
         uBK0t5L12wi/WS3bGW+wK8/Yz4oxFSLw2vl9ItCZAjaj/BEumhz+Vi3x41G2K5uGw4ZX
         7HZTVUEoYlDbxLIqjyvE1vXAhB3s4gnHI5nq0AkQD9KVe0+CeLPeouZ5JG3nMASFpjuP
         lMW2bRlMlVmXlYI3+QJYN1xNFsaeb5tlXuPgLPkWKwG5ERS7boxDVc96HoLENmXwRRNz
         aNF09d3quADZ7GHmshHcZeHAtJRiagITDL4c2GuqbYskmTeD2xtSr1gOg2KUynaTg5KR
         PRmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :mime-version:date:reply-to:dkim-signature;
        bh=vJlt6XmNiN8JOwuzWs7z8qAgRS2fIsHFCc5wJ6wWpHc=;
        b=vykUoE5kA2cRD5nE8BxxQVQiw3ieUwOZP1E6918jyceCpGNfv2Vd625LufHtE9lYB1
         aULm6bb5JXgbXNNh9Xae84cmCoYGUnOD+GZ089bhuuuZskA/sca3GhGwo168KD/CjH6J
         zqV2mWzZIoY33hUQ1YuI6MpiyB/y5E1f4GBhvVDILVqGkCL5p09TQfTCJLphBPWhg24K
         quHxaPW3fH9LajA00BUPTLY0w3RLi2IWpbv1sWl1IFocoCbNnTC0i9HaeBoJrTTN1lCJ
         jvpKydBwwKWKy35s6f7gBMIBP8mmisb7kW4ylp4KMBmCv2CgrMgbag1Zabm19Pm2z9tP
         gnkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZdCPwF6l;
       spf=pass (google.com: domain of 3embtywykcrmbxt62vz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3emBtYwYKCRMBxt62vz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:mime-version:date
         :reply-to:from:to:cc:subject:date:message-id:reply-to;
        bh=vJlt6XmNiN8JOwuzWs7z8qAgRS2fIsHFCc5wJ6wWpHc=;
        b=Z+BicpSYAiiD/Q7vzuRUU8qJSZyeEMlehzyhP0aWfjXpPLnb/MN1nrqcrBiwgGRu11
         bxsVg7bogfmCySsIUO/Rkhje3aCZy1klaSfqy/J8+Q8zH3UV9dgNGd2X42WkNarbW16Q
         w6LkLk4ehSqrF+F79vo+qVMcTAjVDncHHRzeh89MeoCWjmu45cDpejOrWeF4S95xv8ka
         AhUmcsBdr56mV9Vu5b3qXxzEDQYdk+RoNf0eohp6iR4jqehatjOXWM2QHCF3zstICL7I
         L4TtY72ZeaIF4BFLVH9xRrcthgOvbsVcov8HVvxLQxyEVSWChq3TbIxmgzp+SlmPDxUP
         o39w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:reply-to:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vJlt6XmNiN8JOwuzWs7z8qAgRS2fIsHFCc5wJ6wWpHc=;
        b=Nc8OOP9E7lXHPx6jv+JUBPwxFe0Rn9XvdeLyQzHF70LSyyspLDzYqqRJ5mizGIPr19
         W8bA9YEvP6CpPKlHExGeH1to8Oesr9woEtFYRiU6oDydfIJs6SiiEC+Os6vWx/2cIP6z
         kPMvV28bgvrw5MpoCljfGzor8lVt95JqOwz45GHOlccoqlRkitr6LMV0cNofp/swvHXT
         xSQeHegBszEYsSn7WxtXtLNLZmfb7gKgyOcXQ8FSNYiTJR3gWfhCZR0plW4xFOXCAKkE
         C8lSNXVBwZEQK1PweyOwOgp2ckwWuudDQ0SpA3fxMtvhuP337AxwS7u58t4PfB3spxqU
         vM3Q==
X-Gm-Message-State: ACrzQf1WfwBGrP6PifIMwIssrn81tXYi5CxcZuLYidmzR4XPq4KgnKuR
	k25Bo+mxsO180a/mkh2mLlA=
X-Google-Smtp-Source: AMsMyM5Bip0eiP6lToxMCbQ8vgAik7BqFFNoxUO9Z8VVqYX/50pe/bi6Rrep9v5a08uTbS6393pAnA==
X-Received: by 2002:a05:6214:21ea:b0:4bb:ecf0:bc5 with SMTP id p10-20020a05621421ea00b004bbecf00bc5mr54932069qvj.86.1668112507508;
        Thu, 10 Nov 2022 12:35:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:261b:b0:3a5:9266:3e6d with SMTP id
 ci27-20020a05622a261b00b003a592663e6dls1752781qtb.3.-pod-prod-gmail; Thu, 10
 Nov 2022 12:35:07 -0800 (PST)
X-Received: by 2002:a05:622a:1984:b0:3a5:931a:8280 with SMTP id u4-20020a05622a198400b003a5931a8280mr1176879qtc.31.1668112507071;
        Thu, 10 Nov 2022 12:35:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668112507; cv=none;
        d=google.com; s=arc-20160816;
        b=BywMcsrXO2JKcJlrnRdr9XyCvxEG7VGqBFIafdewaFEwXoNNwbdBEytbsuE0jQl4dl
         WbRAtUgtUknwyLOLEdVvzdCjm7DuiiV5v6OpsUdQr2rWOJx0fO6SP5TEyQEAqxlNq+Aq
         9Cv32hmgWxCHOJtDZMbA2pvxp0ia9b/AgrKDZIiNYbkwyIEHME+9XQ/PHn00seaPM1EU
         fKIFjJrX1v7pVaW+kIIjTsjJ70TXLQ1smQvTkEV6f4R6H3oLKYhFfPeOD5xOLWPeSZYX
         hwWuNkL/ujcoRcN5CdN3uSKeV5F+vWQ+xt0JmhiOLVgjUd6I6lu7qJu73emOqlmhw7wm
         QYYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:reply-to
         :dkim-signature;
        bh=gTisTjUIrNkCCyr4cBDa7S6OIhSv9dwgO2DzrZiSE80=;
        b=EffW94MagFU1xeFXrn4O6eQtUu5KqeLZXXk9HtqJVRGvU/GG6cPZrYKr6rgsjW307m
         XlH70qMJPZEiZ625Urzz6YMHTl+l3nf9S7E5ixXmWJZmqW7xmY+57yRbUfEJ1dA/IbKG
         Jcq5j7slSYc0llKOvhEAZC7tA5wt3wLVVtDSPfftyYo7LXwAnKdcwBNbRHzY97RKJsVL
         1bv9VsntZ35r2b2wC7XAmEuIrBRtRt6VVQFaj+aCBqR7psMz5jjuLKb1PPU/AE8suqgS
         Z8wox+JzyGdOtitKwCazM3ngP2AtiwX0QdHGK5YNdyP7s0F7awO0Eg+9pwMQlCfUPAyL
         xQxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZdCPwF6l;
       spf=pass (google.com: domain of 3embtywykcrmbxt62vz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3emBtYwYKCRMBxt62vz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id h5-20020a05620a21c500b006ee9c67dfb5si14122qka.4.2022.11.10.12.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Nov 2022 12:35:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3embtywykcrmbxt62vz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id h67-20020a252146000000b006ccc4702068so2732912ybh.12
        for <kasan-dev@googlegroups.com>; Thu, 10 Nov 2022 12:35:07 -0800 (PST)
X-Received: from zagreus.c.googlers.com ([fda3:e722:ac3:cc00:7f:e700:c0a8:5c37])
 (user=seanjc job=sendgmr) by 2002:a25:1181:0:b0:6bf:bd96:2b01 with SMTP id
 123-20020a251181000000b006bfbd962b01mr62705133ybr.17.1668112506706; Thu, 10
 Nov 2022 12:35:06 -0800 (PST)
Reply-To: Sean Christopherson <seanjc@google.com>
Date: Thu, 10 Nov 2022 20:34:59 +0000
Mime-Version: 1.0
X-Mailer: git-send-email 2.38.1.431.g37b22c650d-goog
Message-ID: <20221110203504.1985010-1-seanjc@google.com>
Subject: [PATCH v2 0/5] x86/kasan: Bug fixes for recent CEA changes
From: "'Sean Christopherson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski <luto@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: "H. Peter Anvin" <hpa@zytor.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Sean Christopherson <seanjc@google.com>, 
	syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com, 
	syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: seanjc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZdCPwF6l;       spf=pass
 (google.com: domain of 3embtywykcrmbxt62vz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--seanjc.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3emBtYwYKCRMBxt62vz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--seanjc.bounces.google.com;
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

Three fixes for the recent changes to how KASAN populates shadows for
the per-CPU portion of the CPU entry areas.  The v1 versions were posted
independently as I kept root causing issues after posting individual fixes.

v2:
  - Map the entire per-CPU area in one shot. [Andrey]
  - Use the "early", i.e. read-only, variant to populate the shadow for
    the shared portion (read-only IDT mapping) of the CEA. [Andrey]

v1:
  - https://lore.kernel.org/all/20221104212433.1339826-1-seanjc@google.com
  - https://lore.kernel.org/all/20221104220053.1702977-1-seanjc@google.com
  - https://lore.kernel.org/all/20221104183247.834988-1-seanjc@google.com

Sean Christopherson (5):
  x86/mm: Recompute physical address for every page of per-CPU CEA
    mapping
  x86/mm: Populate KASAN shadow for entire per-CPU range of CPU entry
    area
  x86/kasan: Rename local CPU_ENTRY_AREA variables to shorten names
  x86/kasan: Add helpers to align shadow addresses up and down
  x86/kasan: Populate shadow for shared chunk of the CPU entry area

 arch/x86/mm/cpu_entry_area.c | 10 +++-----
 arch/x86/mm/kasan_init_64.c  | 50 +++++++++++++++++++++++-------------
 2 files changed, 36 insertions(+), 24 deletions(-)


base-commit: 0008712a508f72242d185142cfdbd0646a661a18
-- 
2.38.1.431.g37b22c650d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221110203504.1985010-1-seanjc%40google.com.
