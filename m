Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBEEI3P5QKGQER3LUOPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 60372280D49
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 08:09:21 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id rs9sf261414ejb.17
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 23:09:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601618961; cv=pass;
        d=google.com; s=arc-20160816;
        b=XWL3jqyR7S74Laa4+gsrGXunLuOzDF2cncJyvEaQQq8sj5licgYKt3roIJOki98lYO
         EYBYkD5QLLe3JlnzCy5DO6Gh230F06VPls9YttPzBwsQ2a2lZSjkmcP9ASZkzKnMHZ5W
         sLxrN9PEqfXShF7nts8c56TPbtyuX4DdczgcCgPr+/VodVCioJuZ6g/pe3ODYLtMO2Fi
         G4FL9/vIYmOjfHtIKsOvv3FzET+7zMrLbsVmkYQyrBVp4T11cf0RT3T2fEUW0jyyotlX
         Fekl6DVC60UvGA4PPBZeF5zLxxVo5MKbO/Cz6GKqxJsqGeqQxeOivKQSNZo2uyjsItqe
         BIOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=odfvYvbqUzcYZ3uCUMIFgoXYyQ2t8qUq8Je8VGz+FNo=;
        b=GYuCh5gNlRwGKYxEZYS6gQb273CTIF6cNYcjaCDvQP26rzInJ5X76JffhLy8IYYZGP
         YWm11TYrd1w0F791SeQVTAUvrJnbf0z6/JWkTS+TE/U5lLwuoHGY3J6k3jbZlh+/AA48
         o1NDWyybCZ2ZZmDYLd9m2axvDSw8wp/SVyO3hWVOGAB40Ji2vQuDGTnWuMCWnnbwyaGn
         Yyd1A9nokGs9Y9B+H/Xl9Mrtt/IyHX0zIMyaZ6Y5nX1C6i15poRtszBfZXM5XU2vCQvv
         4T2P+C3EGhYPIvWyfLDRQB1kyJaXcHRS6j2uQdEhkzbD+8hrgCGrhopT8lWByUP/fabN
         cYKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rBhLzpe9;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=odfvYvbqUzcYZ3uCUMIFgoXYyQ2t8qUq8Je8VGz+FNo=;
        b=MUJxfZmHxz4LQJ7qLWpOzpVx0DR+gVsOFUIUHPC0O3sluMgB8wegptrwHoyd1SQcsE
         Ih6OF+Bqn60R0DP1WgxFMIMjHeKIf3OCcCgsqwUFf0TvOGeCoa4yXnE3qmYOg4WR7iWE
         d/VjFvP0/jIn+dnPnIVVhf0tx9EGYecFqqLyNSWWbcYzSyWN/deHGUo+OHtMqd17igAf
         8gyy76kQL7469Uv9o9DQEBZ8JYOtFFPxL0yVyOKXOx/NqWJjZqdj0my3mdX7vLHhi5Pl
         CEjhkP+MmMjprUOXpk0JN9EVYa/jWx9Cn5p6BEtW421tU6M42bUY8xmPXFIFJYiHDuWk
         yyPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=odfvYvbqUzcYZ3uCUMIFgoXYyQ2t8qUq8Je8VGz+FNo=;
        b=cujPRiVVAjpFKSj02ZQrsNwNKPCeYmyKYtFtTE1LRR4f0rk8WGrScAhzKfR5vS9bGI
         F/z/1YqNL/rPOM2m5aOeqwzXLPLjnb0IE/1ber6pqvuMQwy6i5Z38AwqlhhyLpKyvTSX
         ViGJCnm+NN/N+F/31bndQ50JgrccbXoRQIM8Tq3uwUMZcjDQllU5uiCaXTmCXTzCiugd
         xr6mlYNX/ESc2Uk1TcQVQ0/T3kWLUHAMPLJfHnAinRLWWkTbcp7LNozSG+1LG63Ytb/X
         TEYD4mG4X/6itgmqL4JC/Pz2sho2mczvNimX0197Vu8U0JiEsNbZkHjR+Zcj6albkRTK
         +GqQ==
X-Gm-Message-State: AOAM533SbjD4bPe5D8OaIlv/sbUNCsTl1l4PjjPjnVuBW9/qDWJ6NPw6
	hOpepw+WJB0byxHDXon1Ylg=
X-Google-Smtp-Source: ABdhPJw0524/kve5eaZE+3wzXd5JHWJuifKBm5h+llTo/Cxy+Ts2LmAKRRR29voiB6Vn3SFi2SIXww==
X-Received: by 2002:a17:906:60d6:: with SMTP id f22mr616369ejk.250.1601618961094;
        Thu, 01 Oct 2020 23:09:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:f1c6:: with SMTP id gx6ls155192ejb.8.gmail; Thu, 01
 Oct 2020 23:09:20 -0700 (PDT)
X-Received: by 2002:a17:906:2cd2:: with SMTP id r18mr627201ejr.371.1601618960231;
        Thu, 01 Oct 2020 23:09:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601618960; cv=none;
        d=google.com; s=arc-20160816;
        b=bUan8bM8+Z7L0q4NDN78EuefJ5ClqOJbdMGNz7+BZy5wwAGM/Pr6buei8441cHF1IW
         zx8Apa+uv/gVdaHYVw9Ql6orJkW9rmYPr7fs4MaJ/IHkMc6yxXo6Mi9tHs9iwqVvAhhc
         1xFtgOORVsJocv2h5VsfZfYJECsJINrip4d2cGo7MBskrVbW4PgBmnkBVbrQpwpJ136i
         TDggFSPhQkLK69CWLJMzfdtUwYvxSkJVvAdUlHA85gHEQJImDH51YcObKZ11yAwg2I4F
         oDcC0MEagRq24CoK5Amje72eqUkTHCASctv0EXU5zTL2phCyAt6Tz4sQSKY+skhdreqL
         wPaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ErDIuUWMtALu7PV5gTspIOaPecBO2jLlFmry3dq1eBo=;
        b=zaTARjz+vlFvqRAaQK1bPYnLYJNRZKIq5p5QEnfVJVnSI+5MdPqGjpr9XXMGBVi2Cn
         rOgZKw7OBs4Qbijshj/m6zDOyuYdahAkV23d9MzlibuSABrU3p/0mq5x5NvU8yQMuyFo
         ZsEBwXNvx/0SH7lGoLR/+koWQbIWPJNdSUMI52EQwjI22DwNxss5ih1yRUOSaz+AQT9k
         GGgOUOYh//dwQYGRwD5xv83kskeaC601QmutQp5TKtwU/ejks1Vfsojw91XVqwFvqOkA
         CBdFZMaZ1mnQcaprWEEZbOU4CsidtM02zgGElRQS5zwXjxt06pcX6T/FXDd0pv7cZN+G
         w3gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rBhLzpe9;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x641.google.com (mail-ej1-x641.google.com. [2a00:1450:4864:20::641])
        by gmr-mx.google.com with ESMTPS id a16si21415ejk.1.2020.10.01.23.09.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 23:09:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::641 as permitted sender) client-ip=2a00:1450:4864:20::641;
Received: by mail-ej1-x641.google.com with SMTP id ce10so325243ejc.5
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 23:09:20 -0700 (PDT)
X-Received: by 2002:a17:906:394:: with SMTP id b20mr570705eja.513.1601618959814;
 Thu, 01 Oct 2020 23:09:19 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-3-elver@google.com>
In-Reply-To: <20200929133814.2834621-3-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 08:08:53 +0200
Message-ID: <CAG48ez2yH+9jX40YdzkeiGk2vdwquw3U=GZY8S6WXrCEH+73Sw@mail.gmail.com>
Subject: Re: [PATCH v4 02/11] x86, kfence: enable KFENCE for x86
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, linux-doc@vger.kernel.org, 
	kernel list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rBhLzpe9;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::641 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the x86 architecture. In particular, this implements the
> required interface in <asm/kfence.h> for setting up the pool and
> providing helper functions for protecting and unprotecting pages.
[...]
> diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
[...]
> +/* Protect the given page and flush TLBs. */
> +static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +{
[...]
> +       flush_tlb_one_kernel(addr);

flush_tlb_one_kernel() -> flush_tlb_one_user() ->
__flush_tlb_one_user() -> native_flush_tlb_one_user() only flushes on
the local CPU core, not on others. If you want to leave it this way, I
think this needs a comment explaining why we're not doing a global
flush (locking context / performance overhead / ... ?).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez2yH%2B9jX40YdzkeiGk2vdwquw3U%3DGZY8S6WXrCEH%2B73Sw%40mail.gmail.com.
