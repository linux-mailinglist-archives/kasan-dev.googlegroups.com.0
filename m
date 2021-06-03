Return-Path: <kasan-dev+bncBCSL7B6LWYHBBG6I4OCQMGQEGMYOHNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 65B7939A2E1
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Jun 2021 16:15:58 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id p4-20020a9d45440000b02903cf162bb628sf968974oti.17
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jun 2021 07:15:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622729757; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q9mVDh+ogvzuL27/pr9MV8PyNlWrZMf3gt+03ob2AEupXbrVLpkmtMUHMNFrfNNN1p
         D6BE+6JxYVtEDSeU3LaNYeejHKTyYO4lmevUq9Kq6x2IAQO7SWqXo05JVTv6/qJoIgTO
         WlJZ9zdBgo0TBUWnDcWQntBn3k9bCCoywqwmovQqiiMytrzgzCQGOkDy4JvqCr0oo2fb
         EhsJSLNsJhVdqaooWym9Y1PPcwu+JLvrQRI/6tC0GJte1NZlmWtv/mCsCxh2rB7+IBgE
         mi/9swE++ZxyRjqH0LTYKdSh9TLv6JPaoHIWUGO+BDb3uZilBiX9UGJ9s/lXDNUQlxMM
         dyGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ZEoK6prKK6LiZkpxst01Ol7uteg3JVQSMHw8ZFwRvbs=;
        b=bXLJ1PYidGx3FQOghdhxG2uR/E3/TxemTlNfX2EY9NCXRAd5dboaPL4VjWHV48+Qjo
         P1sO/2o0hHg+/FCJxoMQcfRiEK0dELBsniBBtAcSVh2kpe46jEP4oiRpskRhsaYivcr5
         zg7+YiIBoMze1c3PS3pzcHqElrrQb5GzS9gwGQYWdGbeRkUMusKmtuuWogPjfwJWzWga
         vyCC+Eh1/FT/Lr39w0ZUR1DunHhICsaZLOu9HiEGBYNa7Tk0ZDQg3vwsaTUQyK4O7ejn
         DwoJfWXWBjdocfhVXF0sN1PjjYD4qB6w2ziyqBfFtsIJWV5eCsoy1a+pyNoIo7lHg3jO
         fJGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=uOMCAlcK;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZEoK6prKK6LiZkpxst01Ol7uteg3JVQSMHw8ZFwRvbs=;
        b=narCQL87f9ZA9zNbI13Sse+Mf7hvJUZ05UpyRHxF39wjdiQbTPzXaobWRBDu5ZxYdW
         oCorB2ywtE7/ZTFOBXaDrQh/LaGjtkMv75zNV0e80iQnqVOO0X1kd5rMrVVbmYa+UqGs
         9e/6tnrTNCEu6FbKrYKFEZttlraFHZB3tzOMiQ1xQRhoLc327JS7XKZNxtfpqfqJb5FZ
         Mkn/7/peRGcwUxevnCiFTo3CRvefocUjx3koarv98DB+d1hneml0DuA/yn0z9JwIbgd+
         YspAx6dx/7MDO1Q+1HvCrlYvkwdFKY+b69zU9URDk35LHqlDU9015jpZkxZW1dWNOJcQ
         fjow==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZEoK6prKK6LiZkpxst01Ol7uteg3JVQSMHw8ZFwRvbs=;
        b=uFAeiVoBpxEa0e/SY0rVUGXQuLnADPmlSUJCpnkdaVwuWfOo8ZF32brCN6feuCgMBG
         SJJf6vPyPUssibm7cVtcRD/edngt0VfbSVYaFvxwBGAP20TlsgLASojR1Y8IkTVECm7T
         58DmQ5t006hBkKiuWwaXfJ/z3iVBdDIF5l6hxScWtUUhSjnsZ6ZY97Janh1QhQAvOdr1
         Tgzq1M3m2rZ9apJM0zHQ3Bl6vYpDsmU/M8/MYuz+CAVNvsvVNT7BNKztlMbtWwz/xUPI
         Q95cVZz4zMUdUUAgCiyyE2FAO1gYM1ls2QH9E7BHsjscu0rBKaphDLDnU+CGjC5Q2FYO
         qLiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZEoK6prKK6LiZkpxst01Ol7uteg3JVQSMHw8ZFwRvbs=;
        b=l7C/AcSswEnB2bgwxGsrYSmLus2IHSdDzE0xJ82JxHBbvwcQtbvRtjfTRl27UIi8NM
         L6e+0hzYiRKDsnGwA+kfq56Sh9S7WMOr0g36z7BizZL/blKVaRB0y2MM2cdzJd/UuSLq
         Uq+RdpIXteFbJ3aIt/0dFHOQdJUoXFCj9SvlHhOGdSnVeNm8hnxNnRYFhGlHuoaKxi/H
         RJhfVjvSe/+RoM7+6QBuCnZwVba11M04F7OTKcGhPIzoSaYqx+wKpFzMG2lRmF4dMevR
         ZX41gAXA7+eIui87hZtgN+eY4+hlA8tBFqtBk6dZULyq0Ou88EqETsdcXrnsy3JY3gf/
         7wjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5304M5hmdzE7z9KADyhANtAQ6Oa9QFLk20k/lY1Yf88jrXr6VtBK
	UaOFOXSlOXXtHJrPNOY5ZxE=
X-Google-Smtp-Source: ABdhPJwp5sG9JeQ7qWDvXA47dX450Q5M0GfDNKwsP6msGVkliMuYwroWIo2/qwPhvN1E+ZAex2YUkg==
X-Received: by 2002:a05:6830:1251:: with SMTP id s17mr30860885otp.81.1622729755705;
        Thu, 03 Jun 2021 07:15:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7c1:: with SMTP id 59ls1150650oto.8.gmail; Thu, 03 Jun
 2021 07:15:55 -0700 (PDT)
X-Received: by 2002:a9d:4f15:: with SMTP id d21mr30678121otl.155.1622729755193;
        Thu, 03 Jun 2021 07:15:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622729755; cv=none;
        d=google.com; s=arc-20160816;
        b=XoDhYX9Hix4A+esqiFHwPdSaffAJEHCakkGTa4ULQt6f0Oyxj9BHLpi1isFX+9leWe
         kRPoL3WWsnb8q4E/4mBNx0T5KYo1vE6Z7RqQxZPpgHMTFUMEdOT1de0yDHEwjvNC++Nn
         DxHPRokyc5gp4hJ8nZkJIkrpFtSZf7sfmY9f4N7XhbNiyieTvgoc4bNtIw5icJXcSQ7K
         fEaXpioEcQVwPUXozu47PWnUL2Ar6+I0PACLi7ixLLMp/l/eiborZF+oZSJYQT8VETMz
         LB+gIH14YgXlvcoToXJgDeWQYT93/Ptd2oFZ6RQlVNdBi7xrIUjvlvgF64KO5L++96H+
         UQng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CKEmsEK9QKEcJksXdElwk/YbjKL3k6kwCGWsFQD0D5g=;
        b=HY/inWjDk+RWqpeaCB73PXDnhwov4HszMw4hTywJiBH48la+MBZzyr642XvN3YJxs+
         vEXXx5Ko4wRbcOpc6j7Dxqvn1B119Kt9MBmmhFw313j6mgwiHid4as1OV8WFcY6Gl8k5
         ga0+ntIGOt6KC55YVSniZzeNyw/Q+j8/OMNmdDXMF67XU/2gTExIgWyI6tcqbI9j4GFy
         cjnTGmxeqTD93qSwyVBjZxgi3Vylgwi+tA+v51NBosbMZBCakqtZHgbd4x4l+DkrnfQA
         rsRoCt9HMmEOngx1auyiMGJQS5XOysYDsfx86bq+PAHbMLGBj8yyY07LwJT+nEI1nyHL
         CPZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=uOMCAlcK;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x134.google.com (mail-il1-x134.google.com. [2607:f8b0:4864:20::134])
        by gmr-mx.google.com with ESMTPS id t15si162101oiw.4.2021.06.03.07.15.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Jun 2021 07:15:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) client-ip=2607:f8b0:4864:20::134;
Received: by mail-il1-x134.google.com with SMTP id r6so5686123ilj.1
        for <kasan-dev@googlegroups.com>; Thu, 03 Jun 2021 07:15:55 -0700 (PDT)
X-Received: by 2002:a05:6e02:11a8:: with SMTP id 8mr122966ilj.212.1622729754900;
 Thu, 03 Jun 2021 07:15:54 -0700 (PDT)
MIME-Version: 1.0
References: <20210603140700.3045298-1-yukuai3@huawei.com>
In-Reply-To: <20210603140700.3045298-1-yukuai3@huawei.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Date: Thu, 3 Jun 2021 17:16:32 +0300
Message-ID: <CAPAsAGziPKBpKJ7HGGHwEXuTuUXwQnscNQX_LNfCdM3ZcDrW+w@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix doc warning in init.c
To: Yu Kuai <yukuai3@huawei.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, yi.zhang@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=uOMCAlcK;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::134
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Jun 3, 2021 at 4:57 PM Yu Kuai <yukuai3@huawei.com> wrote:
>
> Fix gcc W=1 warning:
>
> mm/kasan/init.c:228: warning: Function parameter or member 'shadow_start' not described in 'kasan_populate_early_shadow'
> mm/kasan/init.c:228: warning: Function parameter or member 'shadow_end' not described in 'kasan_populate_early_shadow'
>
> Signed-off-by: Yu Kuai <yukuai3@huawei.com>

Acked-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPAsAGziPKBpKJ7HGGHwEXuTuUXwQnscNQX_LNfCdM3ZcDrW%2Bw%40mail.gmail.com.
