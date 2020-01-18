Return-Path: <kasan-dev+bncBDYNJBOFRECBBDETRTYQKGQEKD74XTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id BA3F21417AF
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 14:35:08 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id b13sf11713269wrx.22
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 05:35:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579354508; cv=pass;
        d=google.com; s=arc-20160816;
        b=t8PNYkMDT0o/N5mh2gl9fYo16HnauQfTJUT4fBbgZUQvs3NjFJj3hSbMsQS71nGzUz
         sWS2xF48hkoDbhHIaTZl6OnY6CiYGEYimRsDPRNHzaYgXJa8zKEkq0TjTuGczDNZ0Az9
         suij+BKqoY2TAdxtZ0vCzyBXHtmr7C/hVC5gFZRRRkX+YF98ej6XUiz+aYdLn2QXp0+G
         UaikOfrR++coWxbRWMNnROkBLVMlSo5xXUQh1vhX7w7/WxElrAQjAl0dPKevQIqlb/57
         OvbPUiDjCybEEtJ0Np9ZwtSsee9OWz8cybgQaIIJRNQMhf8ypbV+UjXvTrFVQac50rJY
         DJtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=nC3O/M832m+HyUdsVm93EEZ6tZr99u4lEpC3pjdwXys=;
        b=oQV7cV247uF11cHlbUt/DMotfXi0HdkJ8kZobmZaDIcjGZ6LDJDpqtp+QAzQ1LEMb3
         kZ+OHgnTxgRIhnhjyejnQRp4vbQ4hBKf672F4d4CdxZIIHPcVqJwKTuypF72DmW2LS8K
         l51ucxwgAX/gj6izCBeVFifsmHA0/2Ax/xJdvsWKxy+OovMHxuQ86OM1CBOVUOtUbLe7
         recRLakpWmeR9dgypRwpjqg3se9Sqt5Koz1OVHrgdHMFeNKmeLRZF6FBOxbCWRPMbpHP
         0NQvupZxkwnv4aqseLBVaXOAwyk3D7CwSjuAK1/WouyOsmYy/LEu3cxmGuKtNCosPBYJ
         uPRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=WgOpWoDs;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nC3O/M832m+HyUdsVm93EEZ6tZr99u4lEpC3pjdwXys=;
        b=bRLn6XDgacqYOipsOCaaagx2kL+FjkiuB81icVXnATjYFiNEhenE+mjzsTHXQ0x5yd
         7e751/m9pHls+RZBJDjmCXYo8B7MTBCQ0LtWlo41PPW6sg7qEZM+CIlqMWk0Slo/0492
         pbzBo+WwJjMSiyNm23szYySTYvBT7CPtkeMs8k3cXlyl3+yhJ1/9QSjitOLSx2EUOCMQ
         1D1wCfPlfb0x1j412R2nnxtCoj64mbNZt/wAnqTc0eeKns6oH2gh2RFq01OMkLZtjSG3
         oYAPYkewYLuKIiMRgOgPSBZksqwXgHwsPRZMDiocLQ9uEhpxlQu3n7gBxv73a7Ce2Y9r
         iJaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nC3O/M832m+HyUdsVm93EEZ6tZr99u4lEpC3pjdwXys=;
        b=WDMLmnjJbz3sfQG/5z23y9oVbVrKMHT5Q1BHMLxRiwh3y3KOnJJcWNl144qxO485Ii
         IVUSb8xdRGhVSabdfdtbzmhSWYxyECNUWTtiqG3/QNsJzodpIJeNnRHxU8+M+eL41zz3
         YMo8BKAIm0Tm8idMtMwdp3eLP/OtGkfHQqc+XvtA9EHcNTqahzs+RSKUx4yfOad111kN
         VNsg3H7yfseTFSyzluQQG4fzeFsXN0VMVOR20XQy3SA+nAVkwBRluySSZQjPHjffzRaI
         zAHeDulNSDrjqkEp4+bP26AYE8Yd+g0pviiD6kp3mq2rag7bk6wsJFkXKQrTpuYuQGNj
         t5CA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVoJzpW5M2VvSWj5FKHDz6wZBJScZ9X35sWA9vCUjjQAvVvbHuJ
	2/rO0rChjS74aBqOSM6+/kc=
X-Google-Smtp-Source: APXvYqygdCm1bqbfpwxaKOct82PpMU5dK1FVm2QFOhUQeC5sHRzbvMWJqpCobsSlHf6Y8MrFfuVP4g==
X-Received: by 2002:a05:600c:24d1:: with SMTP id 17mr9663133wmu.188.1579354508421;
        Sat, 18 Jan 2020 05:35:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ebc5:: with SMTP id v5ls830816wrn.8.gmail; Sat, 18 Jan
 2020 05:35:07 -0800 (PST)
X-Received: by 2002:adf:ffc5:: with SMTP id x5mr8581514wrs.92.1579354507681;
        Sat, 18 Jan 2020 05:35:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579354507; cv=none;
        d=google.com; s=arc-20160816;
        b=h/PbtLeRBMObqdBfovg0h8vc6AtlBezL/KNKN1e/S/tnWRpXfuoHZp/4lvurdOlYeA
         3kGSexEtFC3ukaXAJEbOfNTsEljwguhgmEGxoYGKRcN4MU9pDXuBpjPjdtLXcC1FrFIc
         i7NPVSES69OGkevEsVZ05OkqQO7LrXQp+JYwtvZrDj3SxH4q2jV07reKjFRyhS7QxBQ2
         e7999L2i4cro942jy8kwEt4owibX6FeWqN61VfBC4Xv2ydSb+l2eggOnOGwXwXqQKg+r
         fTvTlQ6NGkfXyX75eGBTcMKop9sffX4+q+SYYpYCC9KrgV58PawhnRelstzm53NPLFpi
         DFpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v4hcChVlh2NTB+J9TajvHQFod1mYK/8qvcaZx/KVPww=;
        b=JmGxeupDSlRePQIGz1CpVojigAIQvD5Ke8NNCEVzo4SBNy6yOZTVY7CellgaO3McW9
         xgtYncqrJPQRQfLBHURDJbt6C4cNS6zPRCl1PcFkT6QWqm3cdRv4PZ2H0pwNIgUsBrWn
         LXgW7ouOM9bkjLlSXSvjP/9tGs7U4d8Qs44zgUBHWHyI28X6bU9ik0Ut6IiP0gqqanqj
         mOTqYXtZeAtNKR+QGylqf0dw6iB4Aes5iBkV6cAULhVjxQ4RxEB7x0TT1/htZoR7Uynr
         Bibwq5jRsDxZ7UE+B9mr5HjPPujNEiUbPdfv4/dTY1B0YlQhEBpo0WDBiZVZLRLi5m66
         yfFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=WgOpWoDs;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id p23si460530wma.1.2020.01.18.05.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 18 Jan 2020 05:35:07 -0800 (PST)
Received-SPF: pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id m24so10035406wmc.3
        for <kasan-dev@googlegroups.com>; Sat, 18 Jan 2020 05:35:07 -0800 (PST)
X-Received: by 2002:a1c:b603:: with SMTP id g3mr10152522wmf.133.1579354507256;
 Sat, 18 Jan 2020 05:35:07 -0800 (PST)
MIME-Version: 1.0
References: <CAKv+Gu8WBSsG2e8bVpARcwNBrGtMLzUA+bbikHymrZsNQE6wvw@mail.gmail.com>
 <934E6F23-96FE-4C59-9387-9ABA2959DBBB@lca.pw>
In-Reply-To: <934E6F23-96FE-4C59-9387-9ABA2959DBBB@lca.pw>
From: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Date: Sat, 18 Jan 2020 14:34:55 +0100
Message-ID: <CAKv+Gu9PfAHP4_Xaj3_PHFGQCsZRk2oXGbh8oTt22y3aCJBFTg@mail.gmail.com>
Subject: Re: [PATCH -next] x86/efi_64: fix a user-memory-access in runtime
To: Qian Cai <cai@lca.pw>
Cc: Ard Biesheuvel <ardb@kernel.org>, Ingo Molnar <mingo@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-efi <linux-efi@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ard.biesheuvel@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=WgOpWoDs;       spf=pass
 (google.com: domain of ard.biesheuvel@linaro.org designates
 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Sat, 18 Jan 2020 at 12:04, Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Jan 18, 2020, at 3:00 AM, Ard Biesheuvel <ard.biesheuvel@linaro.org> wrote:
> >
> > Can't we just use READ_ONCE_NOCHECK() instead?
>
> My understanding is that KASAN actually want to make sure there is a no dereference of user memory because it has security implications. Does that make no sense here?

Not really. This code runs extremely early in the boot, with a
temporary 1:1 memory mapping installed so that the EFI firmware can
transition into virtually remapped mode.

Furthermore, the same issue exists for mixed mode, so we'll need to
fix that as well. I'll spin a patch and credit you as the reporter.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKv%2BGu9PfAHP4_Xaj3_PHFGQCsZRk2oXGbh8oTt22y3aCJBFTg%40mail.gmail.com.
