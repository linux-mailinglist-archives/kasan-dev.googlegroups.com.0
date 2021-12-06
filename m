Return-Path: <kasan-dev+bncBC6LHPWNU4DBB55TW2GQMGQEJCI2SHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DAD5468FF7
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 06:04:57 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id b11-20020a17090acc0b00b001a9179dc89fsf8612513pju.6
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Dec 2021 21:04:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638767096; cv=pass;
        d=google.com; s=arc-20160816;
        b=UUeze8i3uDbrU4vwk6is5MHbirIRe5izRl2sMMxeePkv6IsKui9JpW9APFmJvD9iBx
         qW+cp2xxwPjxVnB4XWG3rAbFHiz2QWxl/TmP67FrKeI4boPGfx4370KddGGMuapfwFfr
         iPCHoknz22MWqA1p5NmetiMIlOMn5OdoVjyzJjMze8GN3zfA+pXmpWvDS0EoF+SamerR
         ox0dQ9N6g05Tr3hiUZaOtQ+T1aZvH4CNMh7PakmvE8iqBquqG3h+oKH+PpcIHJSn1sag
         HrJWtCB9ohH4CX0ZEZndwAc3dXUNaDJYJmWOMoT6I0CJYlPxAFN6pSo7pvxSgX4FNVwH
         EYNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=MtBYm2eD3NVCnFh7C5QvxgPbPo7mpIQNXCgGSUGzvbA=;
        b=uCF7j/Cs2YdgoUL9UIGV5NiCfHkGl4BY5yRRtIgzU5mUGxkvKP5vmWbl//ZCBsRcxE
         tQWL+LI4a3/SbpGswRn5GY5UYZoW8yTu3yEJ2aQMuIZLCINhNDGSxszQaULkspBgHavA
         5DDE17M8V/n+spA743T2DjT3bKRjvdrBF74B4IWWws8H2lDZx8AUmtX7BlEgplIWaG/q
         D0Rfl9zbOFfbYA6+JxycAl6rHllpuLiUYfXTsPNN9tCdYbacqk4gObShPFBQwYcWurf5
         U8ARsIEfPmCvreaO5u44WOmmFNNQbL5Mx0ZlSmnkVrXhXAyJSsAb2FXgOTWDLdNzj5yE
         d/cA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=gDBAKWrW;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MtBYm2eD3NVCnFh7C5QvxgPbPo7mpIQNXCgGSUGzvbA=;
        b=t8FI8H0vH4W6iKcguH/sqxYmeSsERaRmqKwmbHAz1BOFZareuCu57BwxIhgft+6mWF
         eKCAI3vyQJBgJ/Q7rccOSBQkM4Jllvu44uPkbMEJbQidytKTeILFAhoMiGWOwl2KrEF7
         hErzl5CbnGLjKZKquoRrRi7l7mc5SoAx9thrbhtjPsyii3rJaW5satLFkZ/NwnnDnP1C
         RsYtYmbWLsGIJ97XHHfBbXUTRJkBvXrQNFJrTeKEP0Qscmo/Foryg4ushxgF59pKrm1E
         70/wi7P4Glr8SN08/xW8KZpShv8+xOED9Yh6AIuLSxUg/z8wDzgQr+SVNrdndggmP0lg
         e0MQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MtBYm2eD3NVCnFh7C5QvxgPbPo7mpIQNXCgGSUGzvbA=;
        b=iBgP1mKfRfa9YVbY2ssd+mps+Mq7gqzMj4/BnHQf2+I3gqLAeQENX4OoJeI7fuYRJR
         KM1MaHsBREbNkY8RquW2jqa2y75dL6jRVgTzONa8Qg1I4XWxhi9GD9hgaopCakr75TjF
         63qKZCqpX+Hglnx9A82ML1exnkbyxD6JToQ6mQLaZacJa7MfBrR6Pt0fa3UdgKM5gm5m
         jI0JWalrH0pHFroZJNVN7gVr9y/KjwWgEXWHCIV8/X0LS9eG6LXxBhsTAmR37cmjxDEm
         n7m412pcaYmaONu8tbz5NJiJKs+3CYszf+tdSiaYdLHoXNLuxk0tus/Bd2QUsiiB48eo
         z8rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MtBYm2eD3NVCnFh7C5QvxgPbPo7mpIQNXCgGSUGzvbA=;
        b=j3tEN+03TkYQb2b2+aIHwG1d5aqO+vUYPuXmIV2VaaNX5c+sFEiQtwPOrfkChzJtim
         c/PhzlvK7iXSMclo2MHqFg+FeRVrhZ6zY97doEHKuUzR/k51GjsJOG2IKht4gvVDPCo5
         drxhR6eOM/qdnbSRpuQEfr4tgR0LMYO9azNILY7zODpSkle2M5u6I1drREpTMiP1MzmJ
         6jtz4uTQ9E7MLh4nvO0TBKCJv3PFvo+yy8/hxfBfSZbwCJGS+kUEpUSku/RwMbFkFF/W
         wsf10NL8z1fnDpt4HCEUwnOW3D5p1NpmZc2Uznvncoozc6FzxmzS8heuVP08zH3gkwUs
         08GQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/t9wrYmVU7rl8dn9BrPBpLzcmZstP+1AaGMkTwtyI6BkolGdJ
	Bf9aCZinC1XUdonZHIWDMoA=
X-Google-Smtp-Source: ABdhPJx6DQfNcFwQ64E/ynO2dQNAJwGU6cXra70cx26lAk+lIQn093q/FBPHHqPtCh03vbR0B7eT/w==
X-Received: by 2002:a17:90b:38c4:: with SMTP id nn4mr34565688pjb.26.1638767095807;
        Sun, 05 Dec 2021 21:04:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:491a:: with SMTP id w26ls1298275pga.10.gmail; Sun, 05
 Dec 2021 21:04:55 -0800 (PST)
X-Received: by 2002:aa7:84d7:0:b0:49f:aa6d:8745 with SMTP id x23-20020aa784d7000000b0049faa6d8745mr35041442pfn.50.1638767095098;
        Sun, 05 Dec 2021 21:04:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638767095; cv=none;
        d=google.com; s=arc-20160816;
        b=MG6d/IppEW8aM41S+d1bHdEupRs0P8jSq0OvQBOYcJ8QyKa8oprWPCW9GuAf6SnlXf
         7NU7et0UX05lJ1jW/lPRy3zrdXvgeehc9gZ95NrYxnChtzQiXBLUOrqjW+dBOk/jE7wQ
         GxNpUoKUwEmCAhipPdTwdjs+64xpf5An8uCIl0E4DxKq90kUDW5RUvVcswSWfq4lUvQ7
         558q9uTbdQCh7PujQjXskEw1BTkT+xYAnrBgT7TTLRPpFdrLGuCHGGlg8aEXVUMXXdq6
         Bq2Czrl2b5dcgC8T7E1+GgYpg2hM/VmN29fSDhcDetHNIbFSBO8pJBAtmxlIbGTmqluS
         Dnsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tDhe7b+IhPRxxignxx1nDXp2K4ORmwOTZ8ivGctx3KA=;
        b=zkS0Ufx7VS8TlC9xQUO+4uRQ9JT5wXkpJ3y5oSXQnBr599/8wFerefWmE4o1kvJFfM
         /ktJVgl9JYQpZoXfiQkgT1IUXHgHVeGV2adDa7sZfWUAEgR6fknbBV+uPBOR9GuisBSu
         g7ceWgyPjvLgP/sXNyN4LwW5bMQzDg5xn1MI8qPTW6q6JmIdCjVVU9cvYOu29lNLRP/D
         2h0dh1IGxB8kU4LlPEone+UYlpM4gCOdy8H7Z4qgnsD7x3HR2YexiXrS93SGNf0rvN9m
         9D3VAt0Xb4JSTVId+MDeN3hrBPjhHoW7BS2MI3WZkLD4zwFefMDv7poBGpwB1hOsii0A
         vnbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=gDBAKWrW;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x132.google.com (mail-il1-x132.google.com. [2607:f8b0:4864:20::132])
        by gmr-mx.google.com with ESMTPS id b18si806586pgn.1.2021.12.05.21.04.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 05 Dec 2021 21:04:55 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) client-ip=2607:f8b0:4864:20::132;
Received: by mail-il1-x132.google.com with SMTP id j21so9037342ila.5
        for <kasan-dev@googlegroups.com>; Sun, 05 Dec 2021 21:04:55 -0800 (PST)
X-Received: by 2002:a05:6e02:1aa2:: with SMTP id l2mr31908443ilv.7.1638767094542;
        Sun, 05 Dec 2021 21:04:54 -0800 (PST)
Received: from auth2-smtp.messagingengine.com (auth2-smtp.messagingengine.com. [66.111.4.228])
        by smtp.gmail.com with ESMTPSA id c22sm5776377ioz.15.2021.12.05.21.04.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 05 Dec 2021 21:04:53 -0800 (PST)
Received: from compute6.internal (compute6.nyi.internal [10.202.2.46])
	by mailauth.nyi.internal (Postfix) with ESMTP id 0841227C0054;
	Mon,  6 Dec 2021 00:04:51 -0500 (EST)
Received: from mailfrontend1 ([10.202.2.162])
  by compute6.internal (MEProxy); Mon, 06 Dec 2021 00:04:52 -0500
X-ME-Sender: <xms:85mtYXWw3oDZ0NxfzGmSkDWVDwODn54pQ3vkyqYQpDkpb-hF89cz7A>
    <xme:85mtYflbLFvAzyeoTuOKXu2W8_C3GV0Z_k5wT2Koe6rGc-MOKqU5wJb3_OEdT8uip
    _9vNCV9I3JoCTN_6Q>
X-ME-Received: <xmr:85mtYTY3cVvAZ0O5xOh8r4B7zeUpWVBWDze0NubZ-LuL89xCy_zGvkEaSiE>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvuddrjedvgdejlecutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpeffhffvuffkfhggtggujgesthdtredttddtvdenucfhrhhomhepuehoqhhunhcu
    hfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrdgtohhmqeenucggtffrrghtth
    gvrhhnpedvleeigedugfegveejhfejveeuveeiteejieekvdfgjeefudehfefhgfegvdeg
    jeenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpegsoh
    hquhhnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdeigedq
    udejjeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfihigmh
    gvrdhnrghmvg
X-ME-Proxy: <xmx:85mtYSVyeqXNTvxyxUKsjXeJUcfFiIAmWmDHaJss1eMI7ycPzfiJXw>
    <xmx:85mtYRmcDwTjVFRx64ILk_o3jPn2_It-kF0eEAZKrowIK0kxCG3gDA>
    <xmx:85mtYfeI1tYn0Hy_XlBfSO2fu3lpX1xkTId5vyZ3rVDIn8TYewPeMw>
    <xmx:85mtYQfmvxb8sPHyPVqy-diUzzcHKKuEPRHuW3DggOsRZcB3DDkbF_4ncNk>
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Mon,
 6 Dec 2021 00:04:50 -0500 (EST)
Date: Mon, 6 Dec 2021 13:03:33 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>,
	Ingo Molnar <mingo@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	llvm@lists.linux.dev, x86@kernel.org
Subject: Re: [PATCH v3 08/25] kcsan: Show location access was reordered to
Message-ID: <Ya2Zpf8qpgDYiGqM@boqun-archlinux>
References: <20211130114433.2580590-1-elver@google.com>
 <20211130114433.2580590-9-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211130114433.2580590-9-elver@google.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=gDBAKWrW;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::132
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
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

Hi,

On Tue, Nov 30, 2021 at 12:44:16PM +0100, Marco Elver wrote:
> Also show the location the access was reordered to. An example report:
> 
> | ==================================================================
> | BUG: KCSAN: data-race in test_kernel_wrong_memorder / test_kernel_wrong_memorder
> |
> | read-write to 0xffffffffc01e61a8 of 8 bytes by task 2311 on cpu 5:
> |  test_kernel_wrong_memorder+0x57/0x90
> |  access_thread+0x99/0xe0
> |  kthread+0x2ba/0x2f0
> |  ret_from_fork+0x22/0x30
> |
> | read-write (reordered) to 0xffffffffc01e61a8 of 8 bytes by task 2310 on cpu 7:
> |  test_kernel_wrong_memorder+0x57/0x90
> |  access_thread+0x99/0xe0
> |  kthread+0x2ba/0x2f0
> |  ret_from_fork+0x22/0x30
> |   |
> |   +-> reordered to: test_kernel_wrong_memorder+0x80/0x90
> |

Should this be "reordered from" instead of "reordered to"? For example,
if the following case needs a smp_mb() between write to A and write to
B, I think currently it will report as follow:

	foo() {
		WRITE_ONCE(A, 1); // let's say A's address is 0xaaaa
		bar() {
			WRITE_ONCE(B, 1); // Assume B's address is 0xbbbb
					  // KCSAN find the problem here
		}
	}

	<report>
	| write (reordered) to 0xaaaa of ...:
	| bar+0x... // address of the write to B
	| foo+0x... // address of the callsite to bar()
	| ...
	|  |
	|  +-> reordered to: foo+0x... // address of the write to A

But since the access reported here is the write to A, so it's a
"reordered from" instead of "reordered to"?

Regards,
Boqun

> | Reported by Kernel Concurrency Sanitizer on:
> | CPU: 7 PID: 2310 Comm: access_thread Not tainted 5.14.0-rc1+ #18
> | Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
> | ==================================================================
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  kernel/kcsan/report.c | 35 +++++++++++++++++++++++------------
>  1 file changed, 23 insertions(+), 12 deletions(-)
> 
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 1b0e050bdf6a..67794404042a 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -308,10 +308,12 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
>  
>  /*
>   * Skips to the first entry that matches the function of @ip, and then replaces
> - * that entry with @ip, returning the entries to skip.
> + * that entry with @ip, returning the entries to skip with @replaced containing
> + * the replaced entry.
>   */
>  static int
> -replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned long ip)
> +replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned long ip,
> +		    unsigned long *replaced)
>  {
>  	unsigned long symbolsize, offset;
>  	unsigned long target_func;
> @@ -330,6 +332,7 @@ replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned lon
>  		func -= offset;
>  
>  		if (func == target_func) {
> +			*replaced = stack_entries[skip];
>  			stack_entries[skip] = ip;
>  			return skip;
>  		}
> @@ -342,9 +345,10 @@ replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned lon
>  }
>  
>  static int
> -sanitize_stack_entries(unsigned long stack_entries[], int num_entries, unsigned long ip)
> +sanitize_stack_entries(unsigned long stack_entries[], int num_entries, unsigned long ip,
> +		       unsigned long *replaced)
>  {
> -	return ip ? replace_stack_entry(stack_entries, num_entries, ip) :
> +	return ip ? replace_stack_entry(stack_entries, num_entries, ip, replaced) :
>  			  get_stack_skipnr(stack_entries, num_entries);
>  }
>  
> @@ -360,6 +364,14 @@ static int sym_strcmp(void *addr1, void *addr2)
>  	return strncmp(buf1, buf2, sizeof(buf1));
>  }
>  
> +static void
> +print_stack_trace(unsigned long stack_entries[], int num_entries, unsigned long reordered_to)
> +{
> +	stack_trace_print(stack_entries, num_entries, 0);
> +	if (reordered_to)
> +		pr_err("  |\n  +-> reordered to: %pS\n", (void *)reordered_to);
> +}
> +
>  static void print_verbose_info(struct task_struct *task)
>  {
>  	if (!task)
> @@ -378,10 +390,12 @@ static void print_report(enum kcsan_value_change value_change,
>  			 struct other_info *other_info,
>  			 u64 old, u64 new, u64 mask)
>  {
> +	unsigned long reordered_to = 0;
>  	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
>  	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
> -	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip);
> +	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip, &reordered_to);
>  	unsigned long this_frame = stack_entries[skipnr];
> +	unsigned long other_reordered_to = 0;
>  	unsigned long other_frame = 0;
>  	int other_skipnr = 0; /* silence uninit warnings */
>  
> @@ -394,7 +408,7 @@ static void print_report(enum kcsan_value_change value_change,
>  	if (other_info) {
>  		other_skipnr = sanitize_stack_entries(other_info->stack_entries,
>  						      other_info->num_stack_entries,
> -						      other_info->ai.ip);
> +						      other_info->ai.ip, &other_reordered_to);
>  		other_frame = other_info->stack_entries[other_skipnr];
>  
>  		/* @value_change is only known for the other thread */
> @@ -434,10 +448,9 @@ static void print_report(enum kcsan_value_change value_change,
>  		       other_info->ai.cpu_id);
>  
>  		/* Print the other thread's stack trace. */
> -		stack_trace_print(other_info->stack_entries + other_skipnr,
> +		print_stack_trace(other_info->stack_entries + other_skipnr,
>  				  other_info->num_stack_entries - other_skipnr,
> -				  0);
> -
> +				  other_reordered_to);
>  		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
>  			print_verbose_info(other_info->task);
>  
> @@ -451,9 +464,7 @@ static void print_report(enum kcsan_value_change value_change,
>  		       get_thread_desc(ai->task_pid), ai->cpu_id);
>  	}
>  	/* Print stack trace of this thread. */
> -	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
> -			  0);
> -
> +	print_stack_trace(stack_entries + skipnr, num_stack_entries - skipnr, reordered_to);
>  	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
>  		print_verbose_info(current);
>  
> -- 
> 2.34.0.rc2.393.gf8c9666880-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ya2Zpf8qpgDYiGqM%40boqun-archlinux.
