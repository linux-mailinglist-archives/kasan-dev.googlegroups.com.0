Return-Path: <kasan-dev+bncBCCMH5WKTMGRBL5W5SGQMGQEDA4CLOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id AA428476F42
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 11:55:44 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id t199-20020a4a3ed0000000b002c296d691c4sf16560514oot.8
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 02:55:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639652143; cv=pass;
        d=google.com; s=arc-20160816;
        b=k84gTCh9smHfPxxDz/KsSpI0ckJ8lVqzk2enI9jBnXj2o7fxrCwhIo02YGRCTwVX8S
         2+lzlqienBdND1mjjJjPxfeB7Wy7J1U09pGmKpTgsgZRMGjFNo0FIMmcn2wmAIEG2UKb
         ZJPa2A2Uhki8ixm9LuqXXkXk/bDawOXfHbWC1UTCpmGh9RvA/jkWTaSlZ7xeFh4hcHk0
         s8CkAS+9W6KHEkT6pJLSmAQZY9o25dUrIbxV2urdyqUmTf8CTWrWnqN5MOqLElOQQN4H
         WgMQXACi5gpDtO8E3c4qR0sh1319c+1M9V5aQeckbHMkZvBlqEiAv0X9uqH20UI7yy6d
         nPsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xQV3kY2dLrmXMFLdwzQBQEc5B/EHK2mtctrcYcAWllk=;
        b=iZVOuS5NEvGW5o+CTHp5Lk9y3MAIcCn9YTSEHvP5bTIouaSlJFkzXTruHKycnpLeRC
         UldfD7dd3LqLnTHDdLhAQbfvq66b+CFJjqiawkiqy4z9WRZ4RJpdKfkB2jZ+QFOlRs12
         zUWGIrUgsE/pw51xQ/OzmxYDPq0MEphBcP9BqT31an3SQOXsT0VFpLVw+izcNm2WuRIq
         4Og5bPdx/R9UYJPl84Efuk2k96GoieWoykYNezZlraHF1VKL2DWXW6+d0N/Fi3+rDE5l
         GpILCBJhB8tnkZxerGcRc8OrjwSY1hfYErWC94lm+BCtPA/G1W04UdMS8iwyiQEGlOHY
         RuUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kIH5AwPh;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xQV3kY2dLrmXMFLdwzQBQEc5B/EHK2mtctrcYcAWllk=;
        b=GuvkYGZSehzTeSCXl+VSteAnd9N9NdLjtREQe2jvdG3AsL1ntMvZodmaZgUQh18z3K
         EJNMbjTe9HV9+U8B6aIkdMyCHhwZ7X2TvUBPo0AGrTB/Iku8MMVgoEEXte8VZc/4ErPZ
         dNOarXSwKB6xBLAsxeD47cnqjDh7We2Lf60sRWAwdeW4xW73XEehXLOZdTWT1zmTGojT
         DeDqFJUnaNmPFwOWEA4S+OgTQb4f+dYcjxF3yBfxSW3BNzSSm/2tfD9l+LPhPUH51PZ8
         DkWbk+rfpjjiSpS+/ObSA73IOz0z1/uWUpbug+JlVscSLo9TOFBaeGDhvvlJS9Ot1PKM
         xuXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xQV3kY2dLrmXMFLdwzQBQEc5B/EHK2mtctrcYcAWllk=;
        b=7fMDTVdEQId2bwElfZwFOnvM2qOlalUsmuzg2clfEpEN3N+mcVOHraF4NKUI0cyb51
         o/BEczronMDCxE1G/eRQD3KhizO8F13U50smDRuibSsc15til9rbdLSKF4VO0wzupbOx
         BYWDe6HKQByHz3gsZCoEkH5/w2X0IoCQ97P4BnkGPRBpsuxhQUiGxscdm7Hs9kIU7pUN
         R8DRSQxRKmNPFY8oL/4ecHkfsFgOtRInr5dy+VX0x3FYlzftKAknKnRhB+le9pQp1YxZ
         Uczcee+F6KSqYumGmicQyGfoJRnghx7Kmc2LPCWu25yznDTO48gFx1uMz8Nhvh2eC+l2
         jBag==
X-Gm-Message-State: AOAM532J8XSaMjxQehEnLAzRzjfFyJ7AqwLra3iFFNf96U68vrDwM6Dz
	dmzRqvppur7233Yqqhc97h4=
X-Google-Smtp-Source: ABdhPJyHaThqpRT52dJjUHaLl2cLtZZU8ySeu1S9yaP7xO8E9/U71hOE5fi5dLBzAyqg4HnQEDrLbg==
X-Received: by 2002:a05:6808:114f:: with SMTP id u15mr3687521oiu.74.1639652143401;
        Thu, 16 Dec 2021 02:55:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3499:: with SMTP id c25ls1213537otu.4.gmail; Thu,
 16 Dec 2021 02:55:43 -0800 (PST)
X-Received: by 2002:a9d:5549:: with SMTP id h9mr12286504oti.36.1639652143030;
        Thu, 16 Dec 2021 02:55:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639652143; cv=none;
        d=google.com; s=arc-20160816;
        b=WHC8AShmu2G8HwccGV5Mio/Rc1+hZ7QfTjxEVmSZt1E0179KaVAkKrqY8SEDZMStZQ
         yXlsJlc1nzbOSdMD7+7D3i9lZPfujzlHoIGeQAQcL6Y83506dBaaD1QFORlYb8o77qXK
         ihMi7VxdI7bBh4DnS0R8L64cc0QuJLqv2zCIfTsCY8xp+6o4OBck536Ag2sEGEn6+UxK
         LyJKAZjAb2lM5FgaqZI9qItzATWxWEdEAskNsKDwiTcDxFs4TxmtqZ3mCfZutEPKMhKQ
         pOXyXCQtEFGWN4s7ap1JI/xe3IIFIG2Cq3/AtlHrzvT1HorZQJSpJtrLcp7qdL3vztZu
         UTKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MrDCPm6/+BD3TmuHng5c6ao9ZVxI0GzI50LE4A+AUMk=;
        b=DJjgAYdQ3Ssrk4Wbfy/gspH8pho2QGm6YyCKJQBzfBUCpuMy+0X1mtSXKvd2aG8Ur4
         CcVCr/w+V3AtIPyRTIj3oA/j0FUDxWj3R4UnOH19KrreSovcPLQJJy8/f1+51L4Ioerv
         NqiNsuK3v+RucRokqt0LFokR1q+weSbtcIYWJX34d+3TUfaTqypDZWtsanmK7Xho+GKk
         miei7700g2cxB8z3Fe7dtfJkQ2z/IyeD1jHWsKvcocIgcdKWMn5PjE+wFFu1Hzaf1CsB
         7dKLbRHD/9aW2BnoEpTjZ1m3BgxA9sGJEd9vPmMUvU2wb34C8NgBCjARl5aYbIqBY3C2
         +d2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kIH5AwPh;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id g64si334852oia.1.2021.12.16.02.55.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Dec 2021 02:55:43 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id fo11so1790635qvb.4
        for <kasan-dev@googlegroups.com>; Thu, 16 Dec 2021 02:55:43 -0800 (PST)
X-Received: by 2002:a05:6214:411a:: with SMTP id kc26mr5554605qvb.113.1639652142455;
 Thu, 16 Dec 2021 02:55:42 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <15eeaed5bb807dba36e36d17a1d549df8e2b752e.1639432170.git.andreyknvl@google.com>
In-Reply-To: <15eeaed5bb807dba36e36d17a1d549df8e2b752e.1639432170.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Dec 2021 11:55:06 +0100
Message-ID: <CAG_fn=W+FDpjxipKvBjovxzCxodasFD7W0vpv1sUbEM75J3Edg@mail.gmail.com>
Subject: Re: [PATCH mm v3 19/38] kasan: reorder vmalloc hooks
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kIH5AwPh;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Dec 13, 2021 at 10:53 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Group functions that [de]populate shadow memory for vmalloc.
> Group functions that [un]poison memory for vmalloc.
>
> This patch does no functional changes but prepares KASAN code for
> adding vmalloc support to HW_TAGS KASAN.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DW%2BFDpjxipKvBjovxzCxodasFD7W0vpv1sUbEM75J3Edg%40mail.gmail.com.
