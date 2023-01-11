Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6OO7KOQMGQEEABK43Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AD77665B13
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 13:11:39 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id l17-20020a170902f69100b001928d6b3efcsf10390606plg.2
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 04:11:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673439097; cv=pass;
        d=google.com; s=arc-20160816;
        b=cVkJfYOpY5LRZlqWieJZdHuJnG1e6wS9gj+m1m5MXD00e3YTlNL+THJJojofNu6tt6
         geHrHsuw/u/iTLeqeGTdnGiCAjpx9wv5wFd7ucSb44nTjzCNj81NFoaLlFyCc5T63+iw
         G0nzI6PrN8ZekrrV8ImdjsAUHxV3DhSrEv2ZJ6AYkkUJtV2mA13p7ew9nO0fAfxugKuX
         +PrEq0qiMlNFvdwWgDWPsDlLABz1rfmHQqWzDnGBAh7ZRpHQxoJoqDiYsCfXeC+qpQTA
         qYJWp35bRE8MG0hutnRZZ2IcGTp8h2fRQbJlANma9ndl9W6titTwz+UqA4oQXsWDNfT/
         27cA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2PEo8cI33y5pE2zhLlg7MS+NtSSVa4r96MX/6ArzzG0=;
        b=wb87aMqZKZptxCG9b7tL6NPUizZ/ItsPtTol6rMhugI/2D4pt7YyJS5rCY3BQFxsMM
         /MYxKxv7ltc3SdQ32KcVNs9TElAIB4MOKfTVEsIFr8phykkNqqVdeGc1GVJWAKxnFgit
         ktSg2VnnUYDUwVev8oH8qumuiENxRg1TA8dcB0Z5zGlbqshILzA4f2ZPxaatD1Kt5BPX
         Jr1mcWZN5fFyfJyzqNjPuJhtDaSdx8ItAh0LW2AhjzJ+LI5rdCJhRsxzanTlGjZRtx3D
         ifINr+bzNl/RnI1PMJCkrFAWk1r5u+4b+BsQbqipPs91cbGnYPDSCMmsvM9VN6orD8K/
         IGsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C9cnI762;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2PEo8cI33y5pE2zhLlg7MS+NtSSVa4r96MX/6ArzzG0=;
        b=bIruImsSd/wForwFjCG5wPFfjA4IsRfj47hqndoN+ehs1h1CFEjk1tdc2yxIjeOjt8
         KtYUdpTATqEPDavSr1hU2RfT0ZqWt+zU+5i8rTsLpmJY4Jc5r7K3EK94+udWq1OBkY1y
         e/k7FY6V8Z86f8onGTxzNVDZ0BQh0T0jOwW5CW+Z41y0J6Ig5IcD7w0UZjK4lHIyPHcj
         ELd5zxMOM22GV1hN1OPaXE9xP0BuYzIftTnLnUXVrsSC7O147MgWwNSjNbej1NwJa/G3
         13PtyEKXwS6fYRV1iYb6JN5Jd/yrOyC4CN7tF6dtB74Jyl5N6CUfA/A2Fvov8tGTkwku
         uMBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=2PEo8cI33y5pE2zhLlg7MS+NtSSVa4r96MX/6ArzzG0=;
        b=5FiWH6TlqiUaqbjiCKtGr1zmofCPS5amMncADhXnyePlSqc3e+nDfhy9Gm8FBBmqcY
         lkm+37mrYT2ib4jSSvZnQhiJIiPDyiharUQGmTjat7Dp1De4jJLUxYWO6Xljf+zpSegm
         0lhz3/+bvz3nvJVT5yf0oSuOXYuodUkXGXfsmYLzZIBr2Kog8vkD92QDYJdZ8x3AhzqN
         /TQWP0eUrxe3pvvuqRaxZ9MRONPp7CnzfQC1qztGxps/RmTjiHeMx2OeDqBTXbbWNlN+
         aTpSAP9UoZmJ2wMZK3igoWGixCsm7VbcKF0viGj/jEj5Scrn7pG9VnQVkpnpSae5+mbn
         kUPA==
X-Gm-Message-State: AFqh2kqZHdQ303A8nPWnOfAKrhOpb1kY7maF3MJuc5ALuzzX1WHW/98Z
	xwT1YiW3m5T5xFrMYmMibyc=
X-Google-Smtp-Source: AMrXdXu8VZXeiHrYKRLs3zZI/9wzftsUoqMOf9Qkba6IzQvSEGUgJEaoENjSNH2B0CRbxkHrZ+YxZA==
X-Received: by 2002:aa7:88c1:0:b0:581:e3da:9f7b with SMTP id k1-20020aa788c1000000b00581e3da9f7bmr3078739pff.23.1673439097475;
        Wed, 11 Jan 2023 04:11:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:3283:b0:178:35a3:84d9 with SMTP id
 jh3-20020a170903328300b0017835a384d9ls11015398plb.10.-pod-prod-gmail; Wed, 11
 Jan 2023 04:11:36 -0800 (PST)
X-Received: by 2002:a17:902:ccc4:b0:186:e434:6265 with SMTP id z4-20020a170902ccc400b00186e4346265mr85902606ple.2.1673439096709;
        Wed, 11 Jan 2023 04:11:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673439096; cv=none;
        d=google.com; s=arc-20160816;
        b=bNtHmlG5iLVa3DCiS/fsF8TPxPHltUt07uMnlojwmchZ+qyc7oWCYyRaneXDPxqBSK
         U/2qjCWsp+OEZMLG6YYgu8zvp2VavMokLWoL+P0MuAvURipas2/L/i1UAu/vIjJJAAD7
         fzXa8rjlzzWObpwBPd95Jo9+gx1wH/CGYAj5TI3j6bZeiTPloH0IN4e75WWawKHwA3Wp
         +2JGAdEWM2HM/swt7tm/JgHXBp+xKoZzDS5lFpnxIlb1J6w60oimlvAkYITs0GQxpNRh
         51ucl8NS/73P1972jinX+X15jGPP8xRCyrxKXUW+V/v0rg7veWfk5z011M8KR2XHC0wT
         AuIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RUzF6lCgQp1o/2q+i0d8WNfiUX6YauMmBM07mYYsz+8=;
        b=FXoLC0zgiKvhvp6lBXEHyrLRx/w3R1h7lkbUMk+Fj5Hfzy0kBuN9MHzpbONP2o9Q/M
         P1f6NPBOA4hjM2n4sDXJm25fgmgXPULJkiGnZhGa8nicowovKkwoLvlmNp0R+47Dw2go
         8IFGh7MaGVk5hNpWL/lWMhPXwSZPAHdWnrWM0bKSPE9cqlcs9/3RDkwZ685+2MsDfkpx
         P/UCXkCdIglI+uXAGRhf1g4EnPS9pOz/dVywWxEuqwOPHNTm5tzXIKqVWZmBkd68egIU
         /VavtXKkdCTa1sVQ8isDESo0W/2skLGnE5q2u53+1wwaIMLvHGzc1WZAU6LVwEuiQJs8
         m8Cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C9cnI762;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id s14-20020a170902ea0e00b00189ad838080si1137309plg.8.2023.01.11.04.11.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Jan 2023 04:11:36 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-4d0f843c417so78391017b3.7
        for <kasan-dev@googlegroups.com>; Wed, 11 Jan 2023 04:11:36 -0800 (PST)
X-Received: by 2002:a81:a513:0:b0:4b5:55fb:6cbc with SMTP id
 u19-20020a81a513000000b004b555fb6cbcmr2804118ywg.10.1673439095845; Wed, 11
 Jan 2023 04:11:35 -0800 (PST)
MIME-Version: 1.0
References: <202301020356.dFruA4I5-lkp@intel.com> <aa722a69-8493-b449-c80c-a7cc1cf8a1b6@suse.cz>
In-Reply-To: <aa722a69-8493-b449-c80c-a7cc1cf8a1b6@suse.cz>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Jan 2023 13:10:59 +0100
Message-ID: <CAG_fn=XmHKvpev4Gxv=SFOf2Kz0AwiuudXPqPjVJJo2gN=yOcg@mail.gmail.com>
Subject: Re: mm/kmsan/instrumentation.c:41:26: warning: no previous prototype
 for function '__msan_metadata_ptr_for_load_n'
To: Vlastimil Babka <vbabka@suse.cz>
Cc: kernel test robot <lkp@intel.com>, llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev, 
	linux-kernel@vger.kernel.org, Christoph Lameter <cl@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=C9cnI762;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112b
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Jan 2, 2023 at 11:01 AM Vlastimil Babka <vbabka@suse.cz> wrote:
>
> +CC kmsan folks.
>
> I think it's another side-effect where CONFIG_SLUB_TINY excludes KASAN which
> in turn allows KMSAN to be enabled and uncover a pre-existing issue.

 Thanks for bringing this up, I'll fix this as Marco proposes.

Would it also make sense to exclude KMSAN with CONFIG_SLUB_TINY?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXmHKvpev4Gxv%3DSFOf2Kz0AwiuudXPqPjVJJo2gN%3DyOcg%40mail.gmail.com.
