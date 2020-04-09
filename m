Return-Path: <kasan-dev+bncBCMIZB7QWENRBWM6XP2AKGQEOPBB5VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B38671A3007
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Apr 2020 09:31:38 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id b16sf10996174ybk.11
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Apr 2020 00:31:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586417497; cv=pass;
        d=google.com; s=arc-20160816;
        b=zKjJl4TycMAWGTn5za6W1B+jaWGcy+3frpmKiGux1ct78GRLv/pSa5iAbxzYVCsfxc
         lkjYD2a7EqA29lhpuhPl5SXy3Q+3m2NP5L3B1x+pIezGIewKhA0DW5TtoLdDZY4jmiCT
         +zlJsbdKWRlBMxQN5xHTtehbAPPkRIBc2BOqKcbIvTlROgV0+H9SeWy2xMioqF4vNWLz
         Vp6EQn9EVIjK9H3X0RHqSdbBe1aBd8wQ7Fgyvjg6IxFyN05dnOH1tc6BcR9TMbp5v6KF
         hx2/DgiM3YKcRoAJkLwp1d9ElXkKfYgt6nsOg7KhuMnFokDIfZjcSzO1ZdgVPQ79XeBe
         /iCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rZ32wsE7WpiL2QwfzgJ1fqh+B8CMe0LTk887rtA8BAQ=;
        b=WIksrURAuetLXG11uw4VIKVRPus48azO9mTSDrZlyUhGRtoylKF9ZsPHHYOlyDkY/N
         nhaDAlKTiC7Qv14nAm2ojb8zqoxAbqmI2RFNKMHi/1h3AbxtftulQJlDj4UR8cDZOB8+
         1UmfxAF86hJNfyMhrbS21Znx79J1lF/OPRcG/8uFLZfN2T1nAac7Kzn4m5y+Xx1cMKJF
         lVOKCwkdPDotqE2KvTYMANf18Kw/7YvJ/hIohW8Du3lkOKWGvWFAlQQaZOSMBl/7Sv+I
         5mrww771HkWLMUiRxAngJ3BqGmPel1b3w0DYn48bkXvPWBBJhix9mYUAij3glNTE6x5T
         TXrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E7BjSmWu;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rZ32wsE7WpiL2QwfzgJ1fqh+B8CMe0LTk887rtA8BAQ=;
        b=qV+dJ0nzPRkYAU2WronrvPikLC1R8ZCis7mM6BGrt1wNG3Va/EOTWvBewcP5HJCSSK
         C2bLnj7k7motaK8nnh0PJUB/j8VhUtvoX1aEdckcqFbwkN44YIegGdWZfzIxYCQtLJsJ
         fPOnjtx9tGjKM5QcMFFNXw4T6gXNmoiskSFCVX1xFm8w9NV3YyjUimJDsNhCY2AaSd6h
         IFmFMKraU65THwaOjSmdM/9ueIFeF0MNe4WnQqjoFZMo9JBF22VDdildINr1WNywGYmu
         VZe2xOVqQSmE24s3v8CNIq5SKj/vD6n+b06WrmSCM/nbvpRVVp9rtHK7Ghx9N5vAlowA
         sm3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rZ32wsE7WpiL2QwfzgJ1fqh+B8CMe0LTk887rtA8BAQ=;
        b=K1TwippM4rn3+Xy7JOE+N9bF9Q8ISM3RTUZWvHKt5ONZ41+Grt22XDcJYg/tOjR6pL
         aCYhFwzRQsQ4x/8q4QPgEsikwEMEHaDZDPkES/tGx36uOKS5H627G1bGCcHHg07d9uC/
         HIhrVfuH/WoHU8N0UiQVJp76v8ilhGCGoxwlTi43XbIjTgJqNZEs2qICQ4XKoPUtTjXX
         Od1ttiqswWee8cG9SMWRGiBJxsaPegIgA8fLGKsXiLAticnRgFtW9r/Y4AYWLgw5C/qH
         nElecfcUHTiUgM79RBpxKi5GFT/LiF0TbnW/mbP5NzvWKHf294+YTisvUTH0eTSxTWiK
         vMrQ==
X-Gm-Message-State: AGi0PuYJtL64J4JUI132tCgnE4AP58854JZTa57ZR/wZNJ6bsb1UBBjN
	vtkZB0E7+QY8ppXFh1TkHcc=
X-Google-Smtp-Source: APiQypJmWd4WA+bzW/LVMc/VmDY/RPAlLuuDJU8LlnDL30cTMmQk24fuLXfx4GikEpLhC3OqN5i7Ww==
X-Received: by 2002:a25:dc54:: with SMTP id y81mr18734370ybe.374.1586417497408;
        Thu, 09 Apr 2020 00:31:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:4f4:: with SMTP id w20ls3623730ybs.5.gmail; Thu, 09
 Apr 2020 00:31:37 -0700 (PDT)
X-Received: by 2002:a25:d7c3:: with SMTP id o186mr19603989ybg.371.1586417497059;
        Thu, 09 Apr 2020 00:31:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586417497; cv=none;
        d=google.com; s=arc-20160816;
        b=MVHZLuIuGsNcLbTI0ge3afzLUb3vCC2tRBj4e7sxXg/GagS5YBQR7ye79uPXZ1Xuzr
         hkvYHj0wSRKzgikr51GLKtJmRxq9U+fVA4NnL4g9Z4U2x7QchEIL2if30xXBIgnYHr4U
         k7xFbW0FboV2mXrrVIQeBcoQc4IWqU3D0XCLEYoW8EAfjfoE5DQVi2eWooD+sPX5pYvm
         f5cAcMt0BP52zZwkU5aoDLPzw0c8q0Mod3TVN8NYb2dTflm6YwrMMXPLxMsvm2vDbMAx
         7mXaEA5pVi8gJPdBLDCfKh7CTyq0ju4ofihF1TmbA+s4BfpxQSCtrzCqEukV1F3gixao
         XQ8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=glVC2sjAUpp4MvZtq1UBRRMXJWzyiqvQqMFGlpbv+dw=;
        b=qgisDoYSgpADHszP1/qd/heNV2CKfeyynVwJnUAhcn/XkL985umCWsQiOw5fcAsj1r
         tZNmkBNAtKxyg4+tPQWoDtjWyRBoliQiU8FTTpOSLXfZDCYse5mwY24mH/xZu+bCkaHH
         AnmntKY9//5XUW0W43dZR0rLEAmnBVwBsuVEaM8p3Nha4qLJOQeu3hgEplxbmQ/6/5Mc
         lBdKRUBmgp6IwZxeotdwqIAdJDkfcuHZPPvkE5fmkSBE2jj80ug7FSoWPAxK2Ep2SGBr
         UM0ACYmj9oD6gP3Xp0BmMtShiozyf9qSmKvFyUw4h1PFLrlRoiDqNtSi2WjLprHv+8xv
         ydGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E7BjSmWu;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id m18si589081ybf.2.2020.04.09.00.31.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Apr 2020 00:31:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id n1so5052208qvz.4
        for <kasan-dev@googlegroups.com>; Thu, 09 Apr 2020 00:31:37 -0700 (PDT)
X-Received: by 2002:ad4:5051:: with SMTP id m17mr11582947qvq.122.1586417496559;
 Thu, 09 Apr 2020 00:31:36 -0700 (PDT)
MIME-Version: 1.0
References: <CACT4Y+YbNNyvoYD7E1Rczt_OmkEuYTs6fDHoaUPFEygYYr_Oyg@mail.gmail.com>
In-Reply-To: <CACT4Y+YbNNyvoYD7E1Rczt_OmkEuYTs6fDHoaUPFEygYYr_Oyg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Apr 2020 09:31:25 +0200
Message-ID: <CACT4Y+bDt_QJ8emH81qcSjFFC75u=cEz6Pc-PTNpoOELNfdBvQ@mail.gmail.com>
Subject: Re: KernelCI and KUnit
To: kernelci@groups.io, Brendan Higgins <brendanhiggins@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=E7BjSmWu;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Apr 9, 2020 at 9:16 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> Hi,
>
> I remember subj was discussed last year. What's the status?
> Has KernelCI started running KUnit tests during builds? How are tests
> selected? Does this use only UML?
>
> Thanks

+kasan-dev

For more context: we would like to get some testing for
KASAN/KCSAN/KMSAN/KFENCE. KASAN tests are being converted to KUnit and
KASAN is being ported to UML. Tests for other tools are in process.
I am trying to understand if KernelCI is something we could rely here.

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbDt_QJ8emH81qcSjFFC75u%3DcEz6Pc-PTNpoOELNfdBvQ%40mail.gmail.com.
