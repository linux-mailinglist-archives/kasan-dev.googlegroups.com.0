Return-Path: <kasan-dev+bncBCF5XGNWYQBRBJNNVKXAMGQEA3CCVFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id AD5098520F4
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:07:35 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1d9b1f2b778sf54385ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:07:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707775654; cv=pass;
        d=google.com; s=arc-20160816;
        b=X46LCCB5SRiy0Plhj7XrJEdfAWaDYpDqW9ktAuyOMqyVk8rkW5nrRJ+/R2WIzsIRek
         Zbm4HHGGiRCjiGJQTkfASffoIk6CSDFOGHMIRljYIgsbkFpL6UeSUvvD4jpEGFo8FCyd
         sFTADbBRzlcfxTUNwwW1Z8juYGnOc21Hdn/1u8y13al6MVyR48z2R4PGidhem+zQeDeR
         fPB04TtuEwODKUt07Ctf8uhUWYypni+1algBvmAK/MlYiEFlNYqWs7xBvMHuLTW2EME5
         GCvTsF/HodOM2zhdl8UH2bSsUlPMvgkme6hqIc6vYXJzTPvCTE0bXRA/98Ue4yFFxfP2
         ZfEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=s07w+zydKbKqpBc3a0G2VpIKHdOmkMAdMaE8rhvUz/4=;
        fh=oZV3hiI5THg6fLqKKQ6i2KggPXpqdEKHB9hUdvzBMdY=;
        b=ff+ojpxhiDd+f4r73GplWjspI6qybA8936Q1Oby40D9Obg+7KFFFtQehwrt5CLBHGE
         wyPynpuRvtl+wBHdrAeEcNZ+wZzFMe+mjS8Wztt57nCrfykWhHnC5IeI26XQwFNjG0C4
         G76kD4m+UmuRs1wGRlf5jwgBIAtgQ3gBN0MBnKkv9qNNs1guyzbYv0jqQgnpBUiEDK44
         2+ved/MRtj4mI2kwH2iGdXreWB5wZwOSWsS5JRzblx9trc4KsjtzilvflSPcLvYNjFWU
         NN2R7D13Ib2vJEc3MZuFu20wkYM2dSYGmkeZgqFvVJ9/zRFgVzNMTemnFdi3lbSAC8Vu
         jdhQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="O/VkjPCZ";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707775654; x=1708380454; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=s07w+zydKbKqpBc3a0G2VpIKHdOmkMAdMaE8rhvUz/4=;
        b=F3UOs4Q+Fab+LVtmAr9Dc4xufLC/yPhQzc3mrHXXvyj5O7PbKifn07ArZxdy74iZtW
         Yq4oGCCZXH8/F6ndIF5Dw80u0qpgHOdrCCK2u++3R4fTsOkc4R0r4PJYAaJWaDejioXu
         6/TfTsXg1y+wb2fw2B1WyGX/B6+LLH+bH7sB9J2eYTbIcS/1fLOPQLgJfIEkuFJk59+i
         VgRBqiKqt1wxhTiqSKNHZIoOCKKLHplebicnrVEPQ11eK5gI7NjbrCiIT4To4od8UWJY
         xXiH+HEFgaDTguoPVK+wIx1xPzZCvaP4w2ro0mNWZI+Omi76+82JCVT/MWtAxftvm2wB
         6dJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707775654; x=1708380454;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=s07w+zydKbKqpBc3a0G2VpIKHdOmkMAdMaE8rhvUz/4=;
        b=RpVe5GxSlD7BGPy7/sHUh4L6XYD5Ur3DcFHKfzGi+bw28ipW4Ri8WHlywEHJx1SSng
         FGgVP5OOe4YCbGgiqetgzrxdnduiv955pwbjwf72vlg/+Z2eFD9U3jBVYy4T3fWmX8B0
         fLtuwHY/cqfZe7vjEgie7fN/O5D6eMKHHtogF3SZ2n1QurmlvJuAq3YQxOf+UrXRZJbv
         kDTu43et57fNvYa6ATJtdGVsZEyjLhK3UeY11BZeDtsIyFj17NmgFZLEkAoskzG1lmCJ
         X1W1k8RGn3hOC77IyNt43nDnj7hNSVBYDMBHjC3HgV7A7TXGRN2iv27fNuSbhS079Ovd
         Xu2Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFH2CjQyW4UARmvhZj0TscLpiwsrKz6NOrbW7loC+u3eG83JKdpSEztTtoU11bmgQLkrxIEnzbBwuIchAIBNt2ctLJBSx/WA==
X-Gm-Message-State: AOJu0YybLgfS9UQqX2coRLzRnftkQqbl3G/gsPzlFRc0utx1NgmckfRC
	ojOgLscRXrQhqRgmrC3ZtlmtNymj/0bHg/a/J/ZI2SsTPWpc/Xrb
X-Google-Smtp-Source: AGHT+IFSuwPtIUOEFqpySwbbFlhJawb3Wc3iSHalEtOineQCw/Z7cHSTXfSnYaQZ4DZiI6kd9xfl8w==
X-Received: by 2002:a17:902:b498:b0:1d9:e18d:2228 with SMTP id y24-20020a170902b49800b001d9e18d2228mr29672plr.14.1707775654003;
        Mon, 12 Feb 2024 14:07:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9dcb:b0:297:1550:fbf6 with SMTP id
 x11-20020a17090a9dcb00b002971550fbf6ls836123pjv.2.-pod-prod-09-us; Mon, 12
 Feb 2024 14:07:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXisbXQTJHJcopnAI1I7qQSF4RqImCx++q6Qcr/xfIF2NiLnm1X1AyeCwcQcimsKnZyI16T8l2VlRixWlryL8zSR0msl/BwnS3ZZg==
X-Received: by 2002:a17:90b:4f89:b0:298:9688:56 with SMTP id qe9-20020a17090b4f8900b0029896880056mr2442495pjb.9.1707775652630;
        Mon, 12 Feb 2024 14:07:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707775652; cv=none;
        d=google.com; s=arc-20160816;
        b=d0lFOz5fPSVJ/GqX9HE054Ho93TrWZTmxT3ec+L6x7mDbLk+p59SSU2l8FAxYWM5e/
         TRC6rfVMICzQ2SUqt4knNZ2HgG46GaZU85D7mdMmP+TS1F/HgliwaxCr5e2+WvotgfJk
         W7teKNuTXZTju0Vwcd1n1amrKwOBs9oJ+rzQ/zitjV/BNWBkVo0Hy+DXUhs6Uroh4dfC
         wqRV5PtV7g6jWbTtDUfxnlTnGTTnN3t/aOaSekTZBXXxFngos/zOLGIhDrFrp6ZdyZi9
         1asl0GxpMsNGdT/U/ExLq6caYg3MTqvzYPnbnFd9nmYTgE+PG7F+2pdraKY8eh/1IqAx
         xREw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8TgitNbd1mPIu/vo61kw5GTuium5jPqAU8tOs86SzdA=;
        fh=WwPjvemRV7yQdi+vUzj7e+OfvcodwETC4ZapqvN02+8=;
        b=Yx/MWFjXX3nK1hBaVemu7f2PEbqYRanfDe/0xHldm7IPKqoB+rXN0RNQj/1as7dBIT
         mvdOb4kSJUqr00C3c3ueq6Bskg44DP4auYA+71dfynuHEjSGQWrAbyCM/W8Tu41e6zdJ
         N/f4tBoAt5e61xgdD4kvORJRHvEe1Hhyw5I44/qPlEyA8Qnc9kzJ0fHHf8ijeoK1TcD1
         SparZ9vxv+QaKJQQVsaD6Rc0QKE9hcl2zL8GIK1KKAd/tDoUKqNxTR091EGm/A1RKuGL
         eW7TF20bQm6jocB23OHOIwyjbAtLEp/oQ7Cte2xlci08a+UnOmET++BVwb6Wbrlro9nH
         AAfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="O/VkjPCZ";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCWWNIHIjSQYc27xMydtVKzQ/9S+HHRTdlVHohTagqEOqcaI6YNbcIFQVV3E7TPgsk/02spEan4uBhuVr9v2ddAM4LAcEcrS35krvg==
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id p1-20020a17090ab90100b0029707e11694si132448pjr.1.2024.02.12.14.07.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:07:32 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id 41be03b00d2f7-5ceb3fe708eso2595936a12.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:07:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVWJj3E/EmU7k6h74J0iy2WMcZj40c7Etw2zNbKBh7/S1NCbvSs7n7ud9cWkxGfKClsRiaqoYysotdw2cSkDBycOAtmrD/flMiHAg==
X-Received: by 2002:a17:90b:d85:b0:296:1a66:bc64 with SMTP id bg5-20020a17090b0d8500b002961a66bc64mr4846969pjb.40.1707775652296;
        Mon, 12 Feb 2024 14:07:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXawbNc3CWDUEqG3ihU82jGjEtq8ZSX7lqqSpmK0uAhhDxnY8P1wbYRD3758nQuRh6XQlALEps3sQul1JiEdP5OqiF+u+OsEMOMEJvQRMONNJnXz4shIxJ3pq2mR4Veo7/fJaKXzSD3XXoVjA2FBPfdju1Mcq/DyF4yraK0GaTh61KxkNxv4rUNlsPOYCAvIZCf/v2Pf7IaG8B9gJXbNXHrYj6P+mEfqJL5u30mKCpt3tkBUYn3/DQYhfKXIZytkp2N/Qkbstz0fZRaHsROMCbcSIEhdEy3OxcWgGRo8nbNKa4YwSBl/LErFGnZoRlW8ZYPpHO4NjdTfCVuplnQ64zhK5jRRfwakO/iVfR5/2elcRQJLpHCvgSdiIlUhFZaR5yOohhDIKSXqMzhE1xL5KV1GoqfwHHG+W2IjuhYJSWuSA+jookxaVlezj4bSuBAghRAo3ztABdCygzlE4+S0nRVTwWkLWKg+I/6Ii4Gfvb4W4rCUxsi6kHxz25akBz4gFfPH0njFHqUUrSDhgbSTBDA/XIsDXtDYlVA7joFTaC58OmI7pfhO36lh1YJPIAdSfownTSGeUCzS6hvOvHZn6XJ6bld71sjInFRU4g0wzbOujZ92hdQe0y7lVDBRBIkBhhT8voUpQv87feOvvv/GHvw5vc6Z5jhfMgIVx2B3w92EJY8G8+JRiOSW3ORL/qB045DoBGe/r+1quICjXnNrUInaj2XGG6HIf1v+kFZsxYiNPds58vT4b2Jx063heDkvgZasmaSxDIUItXGr3GFvrA6nQl5NXwjZZVqjWp5U8qOuzDc51IsNtGc4Gf+j1UHWubqWVwCaTwNIb4g/5B39oPtnnlZLgPpSJt1Bu14wtYNG6Qs1tJVQnCbvAcl07uPbHsshoRJtbt2kdG9ftRYAG5mtkO7BXeOvpXDyf5aajdWNTsLojJl/izMVuYKgX2Tg34uV4
 NNWZFhs5NeDJA+6B+aHG2ks2tdtSYZ7h7C2QfqLRM1eJccOtaVQlXRDZ6kwnBO9qRlDTq3/HOEMMZ83e2w9ISqKIFWrMqXauvCtRH8AQ1jGcuCHswovlxXadpfdyYpUUvzYTnZ7iJvvq5cKJ5Igp2bsj0PJuNtaLlPURaLjBNVdB/qM65mik0g0l5gL9zRKlgBNKXJIT5NIBVFakVFE3RDwkrMGNv0vUBoPRxEzFPiWu+qS+lyoQGwegg2XkbkvwSNnWZCYyZcdvFCjTjb/AfYpSMrClVPlMZepdTAKISpDcLgf0BrTpNdWL+MHOLwiaid4D8ga0EFupRjWDoQhHaX+atfs4VzrZqVJV/I0S4zcGyayYW6dSl2dJHTG1aLj+2EUETXc5JhO3Yx/Fzv0wr7rp7lqgDFjtL5q3d7CogWA8YBBtFPG2VE4FK8BDU=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id sr3-20020a17090b4e8300b00297289c99e6sm1057232pjb.21.2024.02.12.14.07.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:07:31 -0800 (PST)
Date: Mon, 12 Feb 2024 14:07:31 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Subject: Re: [PATCH v3 03/35] fs: Convert alloc_inode_sb() to a macro
Message-ID: <202402121407.A6C61F37AE@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-4-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-4-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="O/VkjPCZ";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::532
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 01:38:49PM -0800, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> We're introducing alloc tagging, which tracks memory allocations by
> callsite. Converting alloc_inode_sb() to a macro means allocations will
> be tracked by its caller, which is a bit more useful.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

Yup, getting these all doing direct calls will be nice.

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121407.A6C61F37AE%40keescook.
