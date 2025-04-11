Return-Path: <kasan-dev+bncBDN7FYMXXEORBY7S4K7QMGQEZXQ2IJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id A0BA3A85455
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Apr 2025 08:40:37 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-739731a2c25sf1048967b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Apr 2025 23:40:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744353636; cv=pass;
        d=google.com; s=arc-20240605;
        b=fqtlihG5vsCwWkS8HdBHTvQSRrG4WDHaIwh20y3VqoTBhFK426V4A18IiXuqLNDAsq
         AwMQaSR8JykF1kY33avcEF7TiGVBCIY/qPrfNGCZQHvTLlSSEhOCD6HIh9Y2p2Pbh/3b
         L90bOR5x/TnGhqm5eYmAGYiNb/9uvsN/hRYTRB2Bs07NhUz3gBKaNKX1/1L1dLEqOF0Q
         UssI32lvbbXfwf79nSMDAO+0cQ9GtWcSNiBUti12vuQ82hiHnd4D3/ueNIGFQoJzS0/l
         yN4BIt06rW4WqvYG14EDkhN44aBSOqlVszwLhQU9hv4S7ItlIcll/ffQ0uFtPBedE+WY
         5sfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:to:from
         :subject:cc:message-id:date:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=9khOQWo5S12oms/PCvFZAMyan8IuE6cDDVmm7ZaTrgY=;
        fh=6vHaAjjw24h2OxAcuNNy6vpZQc/J2Fk78YeROo0I4jY=;
        b=Jo3TYbpnx2MXTzvGcHY7CBA8HdFuu0WHwBpTz2MNJ2J3RZ19aQ2QasaTYM1/mEVhbN
         PFO+M2/jfNheiFogoVaVqKTYS7cUFzsjd7L2ebr2dH63Z4Mjc8kJ13SdgiU4Wf4Y3cVN
         jVeFU0LXwJaiL7X0Cti5u2tYeTmDpsjLy9pNeW9NTlTNU6x65Z+KRjHdDxPLSZsT0onO
         ffLBZvp8zIiHN4A8dZ9yjDIVe7uZEsH18v63AIRBy1unE6FMZANBo/uYCzyL0cLhN0q+
         uqJgX1lgU/9vNo3YHF8F3b8c06YrVqlJJS2ramuAqw4aYpQH51bis9wvuLF/0zt3gEgd
         rc9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BdruUpUr;
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744353636; x=1744958436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:to:from:subject:cc
         :message-id:date:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9khOQWo5S12oms/PCvFZAMyan8IuE6cDDVmm7ZaTrgY=;
        b=xVyq67RsnXgKyqUnFpi+Rwkyq0heWI0ut9j5KtKh4JQqOyY+Jzy1G63Cj3izntxEuR
         31BM/1Hu5MMKhP8j5ATMFny3bp129wKqfg9NKYxyJAWK2SBdcJS0nfy9nyAajtZY1+XP
         XiQFhYANqVmWXXfdVsBusLGGy4fLUtmLfGNTKHYUVUg4m1/57557eDywJKcfdtkQc6AA
         fmJMxkhRc8eyTrDxUtamUp+3eLQ4XgdtQDzoUgY9w0krHJPBSzA1VW0hNMKoqHt3OSQ1
         KkHcqvsGRAYzMjv7pF7HyP4ti8KrIIVfD3jRhLKP3JOLxY0G5N4npwGlwrvJi3ahcD1G
         eoxA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744353636; x=1744958436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:to:from:subject:cc
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9khOQWo5S12oms/PCvFZAMyan8IuE6cDDVmm7ZaTrgY=;
        b=fNTk0MprTQtcMKO5+4xN8EPxzBBsRCexP6VcQcrCqPFG+vaTXD6ChZw017DQNFZFzx
         GBJxkaY2jRDGt9kqpiO5gqrGw39XWsTbZGe9CJ1XGN1AZfS4Z+rqGeCmlD0DvlE9oHRS
         zmXCZ1v2Tse4VO4k6WeO5FxvgihpP8z5n92V96sm5Tcf5b7xtXmVe9gKJ2jj/2hBPW0s
         Acc4fkbEIHx/xYpdbQDCysraxvmwMa+4RuecqEuq5y63iNrWGX88tqbR69FnA/TBp8rW
         GDvEcvdWjUBQHsEwFOJoQj54o0+K/nimBkVRrxVdugbaHwFR7jbn0vBOWJLkhgXhYrvg
         Xdgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744353636; x=1744958436;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:to:from:subject:cc:message-id:date:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9khOQWo5S12oms/PCvFZAMyan8IuE6cDDVmm7ZaTrgY=;
        b=ib4JP0h/AqUfy2/ts1BhseQtaoyeTyYYtFN4xBPiwFHkrJHTBL4mBfO3AbrmoxGMQw
         UddIYtzf79Yy0V7+2npfV73278eXi4dX0flrwjwCbqjdTnfxITX8dZJw7Ue1+Czk9IzS
         j8vVXXi304AfFIEOqtHnfk1b8XGsPi3CYVGJuEhdBzWTcpq1MWFoeNiIxKKTOzDL0XkP
         EHQ8Bmj/IC/Tgp2XYQO1d430Qzt6swy02V3m/YgPxSjvCAcD6fnuLhgWhzF9EY7MBojk
         tJOPZdGImfUiFhC77Dq+jN6PjM7qfroJlIk6Q/JjxdStsdeVX+QELEjT0tXwCweUjJ8Q
         ieRw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXR5oK5CAVZt+/a27pgTjFX7DoPeCJ9DiHa5gsy3o0dvy08rLnA1db0w4YMFYOSUOZE40lXzA==@lfdr.de
X-Gm-Message-State: AOJu0YxlxQPbUuGw5sciF0ZG8LfCpCnmh96Nmukvl+9feovvGTR1GAzr
	sy8aVcFdYyoCbXeDGeDxtNY3ThgFPrN57jnj/OQFnTZOntr8Is5g
X-Google-Smtp-Source: AGHT+IEqE02429jfocHAcZClOROHkvDRcf7UvP+gm+vK49bk/JGBVHiRz7diXbBUpQIgdol4RvOg/w==
X-Received: by 2002:a05:6a20:9f0b:b0:1f5:6878:1a43 with SMTP id adf61e73a8af0-201797a18d1mr2713711637.14.1744353635541;
        Thu, 10 Apr 2025 23:40:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKZOkManiUoIp19cHeoRppsOVflEge5V/ZIg90Ubfjq9Q==
Received: by 2002:aa7:82c2:0:b0:736:9f2e:6b1b with SMTP id d2e1a72fcca58-73bbc4a0f5fls1418962b3a.2.-pod-prod-01-us;
 Thu, 10 Apr 2025 23:40:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVarnzcoAQPfUqAyc19icsceIzo8JZV48M5m2NjrYGCUYqRt1mglcXW9Rm3tGFpO7197g6mO6gZc/c=@googlegroups.com
X-Received: by 2002:aa7:888a:0:b0:736:65c9:9187 with SMTP id d2e1a72fcca58-73bd11ece37mr1801800b3a.9.1744353634259;
        Thu, 10 Apr 2025 23:40:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744353634; cv=none;
        d=google.com; s=arc-20240605;
        b=fkXUS3GytYZyj3cjr7Nk8xGSQIpoGQHcGtXsx7ro/q7U79HJ2Fu+Zjb+Kiq5D6gR65
         v1cJ77U9R7vn7TcK7ut9gUxkhbbouyQYTpGggM+nk1QSViWQFwOQwf6fTen3kpaTBKW9
         pN0jd4flgzM+cMZWVTjNSwKgEor81JyuLK9prJJEZ7LSnL6W+lCZzfX1i25VoZewo79N
         d2ELIcLn6oPT8wMN1mxJR6CQGgPNl0xauo+tNfNV8+5b20zGcXl8QNTolSolIEhBAFJA
         j9EPKdwOq3rRp1J3xSK2p1JufHQdnm/sU04MwGo0wuM23mHBJjxQRA7x0+mfj/yeLlMv
         IBgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:references:to:from:subject:cc:message-id:date
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=WFEK5BUAzhnm7Ls0LSYKvyunOzyOHTaf9tKVCyYIPn0=;
        fh=fltrRVL+ezbUClWwkAJyvcnrweiC6iWc3uijMV4rbgw=;
        b=LRuFvDMGwnrPAJR22l1ERWOAgXEdkxQ5usKxKhdnI7yvVV0ioVNAnG7t1oYJKM6Tuz
         1qU3dC4zsdCSVEurgQZtkQ0pmwr7C9K1BSFDrnxZ3II+qerEkGLdtwnIb1CwtoCGy5FV
         glOJc63ClR4TSjI1A+tp+nfn1oLOvSFlxoNLNS3UlGt3tv9IEusgCUMhxHoQYsw3aG1b
         GRRg++FhvS7vi2UDdQsUd0xg+RDt4LiD0Jo/cCmA5xgjAo9ECYqMw5WDWqF9VHHWYcR2
         L1sb/L+zkjlvmp9lG/qTLVKP7vIQrX7xX9Q7xio9AspbYvEaa328yVW/GQwIi7XXC+eV
         snFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BdruUpUr;
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b029dff2cd9si259395a12.0.2025.04.10.23.40.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Apr 2025 23:40:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-7390d21bb1cso1610660b3a.2
        for <kasan-dev@googlegroups.com>; Thu, 10 Apr 2025 23:40:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW6SxEwkWsmwO0HGNmANkJ1pjR9tZexoNCxo0d89GeVb21lwNPUo2H3wtKdjKWAKVVmLS4sw83aIzE=@googlegroups.com
X-Gm-Gg: ASbGncul9J9Tzfj1/fDkUZgRUSgNsPmlAgMpAYiLeEecL7iG0D3rpVuxaZGfTqZs1/d
	7nGUUH3sp16uonPMeeauZxpq365DibXpRmP0fGzVx1BYcJOEIyuMC6/PKJ12/yZaues9a8+OEVK
	zPazDOOZ9aXw1TO2bZYzbDh4MuF1j6oLPoPAyzrZNW8xfNrI8SjRSTZfEsq3c1hycJcJEhySWfs
	J63+2RCsM/3UqHIXEj5SKxBPoJwF3F4uzd5kbGMmESSm1IzjPP9VKE1A1+xStbAaWX8G8cb5Rgo
	ESX3KMfctszqne8Fem8288lsJmRkA8CpbA==
X-Received: by 2002:a05:6a00:13a1:b0:730:927c:d451 with SMTP id d2e1a72fcca58-73bd12a9926mr2119650b3a.20.1744353633666;
        Thu, 10 Apr 2025 23:40:33 -0700 (PDT)
Received: from localhost ([220.253.99.94])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b029dff3b64sm4083209a12.0.2025.04.10.23.40.28
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Apr 2025 23:40:33 -0700 (PDT)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Date: Fri, 11 Apr 2025 16:40:25 +1000
Message-Id: <D93LR52FZ2QR.399C9CFVNU658@gmail.com>
Cc: "Hugh Dickins" <hughd@google.com>, "Guenter Roeck" <linux@roeck-us.net>,
 "Juergen Gross" <jgross@suse.com>, "Jeremy Fitzhardinge" <jeremy@goop.org>,
 <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
 <kasan-dev@googlegroups.com>, <sparclinux@vger.kernel.org>,
 <xen-devel@lists.xenproject.org>, <linuxppc-dev@lists.ozlabs.org>,
 <linux-s390@vger.kernel.org>
Subject: Re: [PATCH v1 1/4] kasan: Avoid sleepable page allocation from
 atomic context
From: "Nicholas Piggin" <npiggin@gmail.com>
To: "Alexander Gordeev" <agordeev@linux.ibm.com>, "Andrew Morton"
 <akpm@linux-foundation.org>, "Andrey Ryabinin" <ryabinin.a.a@gmail.com>
X-Mailer: aerc 0.19.0
References: <cover.1744037648.git.agordeev@linux.ibm.com>
 <ad1b313b6e3e1a84d2df6f686680ad78ae99710c.1744037648.git.agordeev@linux.ibm.com>
In-Reply-To: <ad1b313b6e3e1a84d2df6f686680ad78ae99710c.1744037648.git.agordeev@linux.ibm.com>
X-Original-Sender: npiggin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BdruUpUr;       spf=pass
 (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::42b as
 permitted sender) smtp.mailfrom=npiggin@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue Apr 8, 2025 at 1:11 AM AEST, Alexander Gordeev wrote:
> apply_to_page_range() enters lazy MMU mode and then invokes
> kasan_populate_vmalloc_pte() callback on each page table walk
> iteration. The lazy MMU mode may only be entered only under
> protection of the page table lock. However, the callback can
> go into sleep when trying to allocate a single page.
>
> Change __get_free_page() allocation mode from GFP_KERNEL to
> GFP_ATOMIC to avoid scheduling out while in atomic context.

It's a bit unfortunate to make this use atomic allocs for
archs that don't need it.

Could you make it depend on __HAVE_ARCH_ENTER_LAZY_MMU_MODE
or is that overkill?

I wanted to remove ppc64's per-CPU page array and replace it
with on stack or dynaimc alloc array in the thread... but
cost/benefit of working on ppc64 hash MMU code is not
high :(

Fix itself for ppc64's requirement at least looks right to me
so for that,

Reviewed-by: Nicholas Piggin <npiggin@gmail.com>

>
> Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
> ---
>  mm/kasan/shadow.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 88d1c9dcb507..edfa77959474 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -301,7 +301,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>  	if (likely(!pte_none(ptep_get(ptep))))
>  		return 0;
>  
> -	page = __get_free_page(GFP_KERNEL);
> +	page = __get_free_page(GFP_ATOMIC);
>  	if (!page)
>  		return -ENOMEM;
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/D93LR52FZ2QR.399C9CFVNU658%40gmail.com.
