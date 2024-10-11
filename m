Return-Path: <kasan-dev+bncBCMIZB7QWENRBZH6UO4AMGQEMNQZZBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AA9A99A178
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 12:35:18 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-5c9465e3547sf549029a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 03:35:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728642917; cv=pass;
        d=google.com; s=arc-20240605;
        b=kPJQl4oreLfZP/98jDpayryDwjbUi7RQkDsAXYa+VOsv2RzcW844RsMNLfGZQ2F2vM
         pzvY6v7vvrHGaPrvg0/C0fVjsj/1vHmLwO8bMMFlq2V0Qdj035NrJItMOmWuIIYlb/VY
         TfHGQGySNuenkA617QjkUmKhNH7Shklrt6H6a64Ew0KfEE0W7l3pBVcTYTiMTDLjMET5
         JHagalT5uuRxxLCjbbuRKxZug0VRd0HA/Etd8ZPfTdOCoouj+Dgg0hYD9W2VGxrSIoGH
         l2vLeHuXeEtwQrni9TSDQvdJR3TrJBULY6x/VpK0yDeH1v/iYsRHMicsLWgs4bibvTNr
         n8eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Fq1ZXzcqh6g+Zirqu+3aodSrn6yityqD2WBV94IOApI=;
        fh=XjfU/4T0OZ/ZHb/ZREziHub9XODdW89VchOSphY1KnY=;
        b=g53Tkhx/uPR/QF4kSlA+S/xoVP4oBcikJ215vHZp9+7xqwTK5nLviAg4x1lvbtbSvZ
         zFvqovZ6lthWREYsROn+dbvBFTSUV6qoHHcN6xWVgV5k7c7sNBZ3X5Z3P7WmyOtqXtNa
         AGtrMvavaKrdyPO6NNA0tiwzbGPvvqGLiT1PNkQ8tWyo3crh+JrL/8ogobSDxExNFJoi
         cq/aT7QfeNKSnbs6MNEyQXY+SbfVXhNI43I0zwRq0d1sXI9/0tysItlxUJSG4KRIsk5h
         Stg2raHdWWBwJZBS/wDslb7iQKIfrco9zYkfNdL0irMlwe9I8Mc8qrKahgrZf5SCI48B
         56xg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BV4P8lLn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728642917; x=1729247717; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Fq1ZXzcqh6g+Zirqu+3aodSrn6yityqD2WBV94IOApI=;
        b=ULZ/ErwdlRAKU2R5TO1nAxjg3lRS2pinpfIBSpkBIDH8GEha+tvMc7sVnY/LpDnLvj
         RjEZeWgZbvLm0cJJTzgVUsJwTGWWysfnqAjyeiAyybpMV1otDsNRkdhw/GTa0JrwbSsQ
         nP9lbFaucTG6lU8SfYyg0EN+1e1V1YyEnl9lOgqCT19PPzKvLsAxHZWdkvIL3sWZO81M
         U8w94Jcby74iKYoNUmDVkMLA9f049uffMuj3/ZXxrC45XSz+Zts4Cn/uK7Hy0soGOWj1
         pWB9/NzSPx8H1pSrDo/MhAULb3YA35V9s2AExHA27nz9YNedDGNXWiJFqhpGZnSaZjWA
         8NFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728642917; x=1729247717;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Fq1ZXzcqh6g+Zirqu+3aodSrn6yityqD2WBV94IOApI=;
        b=YmtnLuOU2WQtoiDoM6cRfC4ICDOxFdk4nGXKvM0JfPHhLgR7FpmJVLP3LEJ7sv2TOq
         RICGVM6m5MEj1YISUcG0PHPKtG7iVbe1webnFD2NStPvFJK2fWTv9jjejQBKgIxfZUfM
         Mv1ijFv5+EZg9BxE53xDGyXiKALjayJPnbRnswZY5Cgo/Y/SbkbduOZQSwLdDlXgZd5S
         KuE5WE0rxRGMi0vWZE9k7CdaP3nP2DxdZT2PIuW8XFv/k6i/3su6SGDvLr2fO1oeavDE
         wPqQcmJYCQ6vyOAzYNqBMB/ZloqhLH65DlILaDMWla+u48gCzO1NFQ+wHN8vJAuewgyV
         RjtA==
X-Forwarded-Encrypted: i=2; AJvYcCUhBuxjaOG8axOR4X/L6aw9PCIjNhX+QmkIx2SgDUj1upiBX+Wk5bzrFczKj6XMBmfIdv9pXg==@lfdr.de
X-Gm-Message-State: AOJu0YzqCVA2jAip4sStXSIzEqzfTPQkoT65v7dfZiDYWqTS4K0vYkrZ
	2PftL3Q7Zy6ZuBHo/7l5jdKcTi5KLSwqiQHoCZBbZ7SErmCYkAW3
X-Google-Smtp-Source: AGHT+IG5StaiUhVUwvTA2GnVL+kzNCPy1El6+UzsE7JgTMyRx9bqTzP4YJHaeQTIVZNwRvhaQImQbw==
X-Received: by 2002:a05:6402:13cb:b0:5c8:81bd:ac90 with SMTP id 4fb4d7f45d1cf-5c948d51ceamr1498342a12.27.1728642916991;
        Fri, 11 Oct 2024 03:35:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2712:b0:5c5:bad2:2aa4 with SMTP id
 4fb4d7f45d1cf-5c9338a8db0ls128277a12.0.-pod-prod-07-eu; Fri, 11 Oct 2024
 03:35:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVfQTp6nm7Ulm3so5joCTkdeup2SbKfEKvuX3EbvkLdTlNF76L1k3w5n98MbD+TlRBaF9FOXf4MOK0=@googlegroups.com
X-Received: by 2002:a17:907:d850:b0:a99:8ed2:7e51 with SMTP id a640c23a62f3a-a99b95a5eaamr175705766b.53.1728642914975;
        Fri, 11 Oct 2024 03:35:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728642914; cv=none;
        d=google.com; s=arc-20240605;
        b=MmgiyIhqRiPto8ZtuvkVRcsmiZXYOXzBz8p2TUD0r6BKj4jKESj5VagFArqHCLX2H0
         UJvPhhtc3swly12Vy1uwW/4PgkaYzQDbDdlpIbuXH5f2WbWFj93M9AV+eTAL+26gb4Ek
         dI+xtU/fqr1cGXXf6zAiXQTj7W9UqAultzudMXZf1+lKg8dkJI38kMWO43EsP7B1kpBa
         W5TiNBBDBwetf6sXGmJbh5ldzFws5bTOEh4u/D9qLYh8bT18d4yy5yrJr5zpEnqZGXOi
         k3uiSflZR/B+yiwiDkY9WXP780vHZxLVn0wJqUkolwWACiWOFQjnFWCtYEdtF9MsuJIo
         H6qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NphLy95X1fXZbYyERmS8gtB29uHtd/dpodXz4Nr7PKY=;
        fh=6jotgMaIdy2UOhLIYQ0RDZiBjP6EHCWr8Ua3FrENKnA=;
        b=IoD4lTDgPM35g3XTuKMblYmMTEs1agE7c/GbLg08YDY6D8VeD1vQ1AgPt7QzpphevK
         D8DzWLjteeM9YggCaa+NKO95cn5grrJOB9U6QZdIlcUeRaKvq0ECkp0kGuM9PGlVN1IJ
         GktNzhihZoAJyaJFD5pUepQQDHmvfqlMsWjMchlRUgsRXLuRR1mCg4bbuylMu7fK2S3v
         4fX1xevrWyQ0CauH/XIdUnDVS3oRZzndBKbNyvJk/nUjcUIrf9qnNYHQ0mu9Czy34IJK
         7vtrEYUHank42ylR5O/lDeAgRFOlRHekhK2JU2J3Tx+SXY5ItoYMJ2GMkRLucP/CbdL4
         rQmA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BV4P8lLn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a99a809bcf1si6780966b.1.2024.10.11.03.35.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Oct 2024 03:35:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id 38308e7fff4ca-2fac3f20f1dso19600551fa.3
        for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 03:35:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVD84Vk80EdelsbzCvGOSWGM6IIauXiCCtTjV+UCTLOWHRJTVqwYeMpMeIjm98oDJcOr+xxYjx96mQ=@googlegroups.com
X-Received: by 2002:a2e:b8c1:0:b0:2f7:90b8:644e with SMTP id
 38308e7fff4ca-2fb326ff6b6mr10778371fa.1.1728642914020; Fri, 11 Oct 2024
 03:35:14 -0700 (PDT)
MIME-Version: 1.0
References: <20241011095259.17345-1-niharchaithanya@gmail.com>
In-Reply-To: <20241011095259.17345-1-niharchaithanya@gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Oct 2024 12:35:02 +0200
Message-ID: <CACT4Y+YpgVYNBNn7O9kzKzS=0kViRMAnAzi6xbk0ssJpz2WnkA@mail.gmail.com>
Subject: Re: [PATCH v2] mm:kasan: fix sparse warnings: Should it be static?
To: Nihar Chaithanya <niharchaithanya@gmail.com>
Cc: ryabinin.a.a@gmail.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, skhan@linuxfoundation.org, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BV4P8lLn;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 11 Oct 2024 at 12:09, Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>
> Sorry about that, thank you for the pointing it out, I understand now that
> compiler might optimize and remove the assignments in case of local
> variables where the global variables would be helpful, and making them as
> static would be correct approach.

It should be easy for the compiler to see all uses for a static var,
and in this case it's only assignments, so it becomes effectively
dead, and the compiler can remove the variable and all assignments.

Fighting the compiler in such cases when we want to preserve
non-observable behavior of the abstract C machine is hard.

"static volatile" may be a solution here. Does it help to remove the warnings?



> Add a fix making the global variables as static and doesn't trigger
> the sparse warnings:
> mm/kasan/kasan_test.c:36:6: warning: symbol 'kasan_ptr_result' was not declared. Should it be static?
> mm/kasan/kasan_test.c:37:5: warning: symbol 'kasan_int_result' was not declared. Should it be static?
>
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202312261010.o0lRiI9b-lkp@intel.com/
> Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
> ---
> v1 -> v2: Used the aproach of making global variables static to resolve the
> warnings instead of local declarations.
>
> Link to v1: https://lore.kernel.org/all/20241011033604.266084-1-niharchaithanya@gmail.com/
>
>  mm/kasan/kasan_test_c.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9d..4803a2c4d8a1 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -45,8 +45,8 @@ static struct {
>   * Some tests use these global variables to store return values from function
>   * calls that could otherwise be eliminated by the compiler as dead code.
>   */
> -void *kasan_ptr_result;
> -int kasan_int_result;
> +static void *kasan_ptr_result;
> +static int kasan_int_result;
>
>  /* Probe for console output: obtains test_status lines of interest. */
>  static void probe_console(void *ignore, const char *buf, size_t len)
> --
> 2.34.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241011095259.17345-1-niharchaithanya%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYpgVYNBNn7O9kzKzS%3D0kViRMAnAzi6xbk0ssJpz2WnkA%40mail.gmail.com.
