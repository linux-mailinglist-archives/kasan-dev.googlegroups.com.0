Return-Path: <kasan-dev+bncBDY2PHGY7ULBBY6Y3TYAKGQE76U437A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 63236135A43
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 14:36:36 +0100 (CET)
Received: by mail-ua1-x93c.google.com with SMTP id h25sf1411685ual.18
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 05:36:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578576995; cv=pass;
        d=google.com; s=arc-20160816;
        b=XRU/6qldy0b91zKBHrP72dQcR0fpenIA2CpYum3K1L5yJGVaFOTyVOc3TV9DK44LQv
         TdpqTBqUScQsh5tf1hqWBn5K3ib2SzLKet9K+/OJqNdJ8ZZYfnhvzMKrD3qJavYRzb1M
         XHihNMdsd9l7sk2ZbLEsm+iGkHD/T4JI4m8cvwn/4XNWy4prVhH/vCVWnmtsoZYXL0Sq
         8IfV0dwH/ciN4o0hdHiSsVcZcO53xPH/PzEAs7EtSalk50xfxxTyJR7JwMG7GSo4gGOO
         LlsvovVyYDm69FBwdDNH/HIsGZEtr/QTSbyhygLr9t1Z0Xp5+Cu5eMhNDX7RTxi6bEpZ
         /LKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=MYkMwq4d+9ZeY3O541jBjjrpJ6Ej7SX7FRwVJFt5b14=;
        b=Ilqfo+ztywUoNeGHCuy9HNvG7CoYYQIKPiWHRkKnMR0RhTrk7BsRcJtKss5Pmm88Lf
         YRSaYymfskxslVpUE1PH0ZqwjEQEmezl+NMO0gxMHI1NuVFtdR8ONMTKpOtxIJTVKFHX
         Oau+eCvNxdofogxMneSnniwu9Uwi87tEH9ARrrsWkxh1E7/c/MpsSM1f9qs589Tw7XBf
         UWVPzJzGIKq110byKbyOgbqtyJTyynD02xOtHJfXqjgaX9DXbR/joJOuzhVW2WitURME
         t/6jt7yZjKrRUHZKT81db4WU53BUV75IOtgOI2JGkHTIJsEU3GTWrB28TARK/slql8+5
         NjKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=rmPFqplF;
       spf=pass (google.com: domain of pdurrant@gmail.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=pdurrant@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MYkMwq4d+9ZeY3O541jBjjrpJ6Ej7SX7FRwVJFt5b14=;
        b=AkO7JZW1vnw+IU3VC5G6CAL/K9V5lT39DK4A5LDjRjhRp0DeemCLQ3Ny0AK8E5T56/
         qcyRn/is8Ab+LuHqeAn1Gf446D2lXH7Anf9PHZH5Z4wDa6ZhT15RqlTUyKTxWNXJ96AH
         LDUQNFeBdui44oLohmF195YQCRy2aNoeFRPnFcTSSCYnQQS7NVRyOnO7VNp+IASM4E3p
         dNK7wP9TyMg75ae1C8+ulCd8TISW3fqMUQVLRzZtu2TC28pRboX2CMKJxsFa4mbvLK3J
         XcWLF98dWu2EMtnlaoDt7RIy4JIC8NwkaHP014qicow2/m7P2sde4zkb3Y68Yow69Se9
         CHAw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MYkMwq4d+9ZeY3O541jBjjrpJ6Ej7SX7FRwVJFt5b14=;
        b=auiFo3NDsJtjKUtjvdHi2LCP3gtuqJE7sx222Oc0nJmSwo+SY7Dy8H5ozlHiqxnPeu
         RCpnTvgCoilB5SriOCONwbZEA6Up1M3rA+KTW0Fr1U1zcoWZYgQLDGTBDcQSslnPvX2Z
         DlM6oEaQOWcNlGf/EjclTVV/suybu/czqSmfJqhFfO0ugyge9SD2IWGwdDbRnwSXeV2w
         brKydruapO9pXzX/k85VIAHRgzQW6BbnsCfefiw7+2XF1FPBIVn3jS4IVLObpxbvvFwL
         fNfKfW4AirXnXud+CpmUo9i8iRXxjtfNpQOlVrke2HmrWTT90fMKO6DFb8vJWqxNiLn5
         2idQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MYkMwq4d+9ZeY3O541jBjjrpJ6Ej7SX7FRwVJFt5b14=;
        b=RtsPrfMIjS803P6B9I0f+VWG4DNTUuymxIfuHW63bETVPrZvSzPk+6VH+FwvKdyhAM
         LMRqGgPV5s40lx3eGHZWpEzrfClJ3tszVAn4t9hvwdaGu7abE7c6QLIB64I3gKEaqKSx
         3eVebALMaHSg/HnuwDudGRbcktQhkImENDKHM0WEjYm0/u9cX+WFHI6b+VOjPMs/1P+V
         cF8n2hqNVqnzTVjJzpZ4Q0mrmHSmUI3DDoA2Qcrr1sjQ9NEZihSch5g9B9b0CtuR2/9d
         4EkF+ntqci1rOVCuStAm4kViOjuAooCQ0FMtqmQY/1PAycRXX6QQboFMoKhrriwoRjzW
         3TkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWmiy5DLTAQbRQx5N4Jt73XTjUR4tJY659DOHJtriB2fLltt7X+
	IW6wL5fpJoENzhnnVudg06Q=
X-Google-Smtp-Source: APXvYqzF4nZI7P/71D7V7wDTgPPLdU5fhYIZOkxL4WDlUOeZrAsCVlKH3UyzI4JHYgvs7CM+Da7Iwg==
X-Received: by 2002:ab0:48cf:: with SMTP id y15mr6960842uac.26.1578576995292;
        Thu, 09 Jan 2020 05:36:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f996:: with SMTP id b22ls185216vsq.12.gmail; Thu, 09 Jan
 2020 05:36:35 -0800 (PST)
X-Received: by 2002:a67:1884:: with SMTP id 126mr5961684vsy.219.1578576994994;
        Thu, 09 Jan 2020 05:36:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578576994; cv=none;
        d=google.com; s=arc-20160816;
        b=PeMPMIH5f1EvnmKa68QdpatCTrBR+TxpDyDBZoh+Hxl0ahYg2osbc/44wDgt/9JbcM
         jve0tbAWW7I2+tbxE1WmXa67JxLFVd+qtenWQqWdRSLV2i7Unfh+rgKFyiUjlVK/m8vW
         nnrVgnJqlmRnXSmGO4rpjzFGfoUieVMV3YukNjFiWZvRTPbnah5PX00KopQ7h3ujave4
         tz7tT9HmHiyfmwQWx1PBy9LO9YN1R2op/tzQvc5zkUD5EavCKPLMKgiN3cG1mLxF/4b2
         2uYns7V/yWrRnu8BDXMHMgK0iSA/xI44Q9rYbJ0gjmHyXrIozDloWUz/zO39rdapMsSC
         xORg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cf95WORT6GX1WJSn8Af/G1OCB1Irn/cMBwQxwXC43X4=;
        b=iW5dux5XNcXvcjXc/rulYnklnLNyjv45piM5n41OV7vhX6rQEqC36BKfP1M43Kp6O0
         DF1np8M+LiWNqw2wBV1G40s3Qd/nGf5VrkVhKjhCaF6nCWeGN9qhjRlZf3vSkOdcK8Ns
         EAmVxTRVimHIrXUn0QVd43w3qa8/UlmAYi44mcYQE/g0fT2aKbar4yzACNp0Q3Vqi+S9
         lpHn7HKgnkc0pDcsFhcPx0Qqx2o3rfhYs53fG5TthzB4tHoLMbfp7+lsjTEwqNT4TasW
         qSIumN1AtEpMNWvtDXNXahQap1atghxVgUjD+bSOUH9yFvxrjJKooEUpbmcz/7aL/lrx
         dcGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=rmPFqplF;
       spf=pass (google.com: domain of pdurrant@gmail.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=pdurrant@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id o19si237072vka.4.2020.01.09.05.36.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jan 2020 05:36:34 -0800 (PST)
Received-SPF: pass (google.com: domain of pdurrant@gmail.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id p14so3407564pfn.4
        for <kasan-dev@googlegroups.com>; Thu, 09 Jan 2020 05:36:34 -0800 (PST)
X-Received: by 2002:a63:3dc6:: with SMTP id k189mr10954174pga.396.1578576993895;
 Thu, 09 Jan 2020 05:36:33 -0800 (PST)
MIME-Version: 1.0
References: <20200108152100.7630-1-sergey.dyasli@citrix.com> <20200108152100.7630-5-sergey.dyasli@citrix.com>
In-Reply-To: <20200108152100.7630-5-sergey.dyasli@citrix.com>
From: Paul Durrant <pdurrant@gmail.com>
Date: Thu, 9 Jan 2020 13:36:22 +0000
Message-ID: <CACCGGhCGcdEq7CC3J0201ETvAd+PZ2fTDNUS3mo599Tuf-61yA@mail.gmail.com>
Subject: Re: [PATCH v1 4/4] xen/netback: Fix grant copy across page boundary
 with KASAN
To: Sergey Dyasli <sergey.dyasli@citrix.com>
Cc: xen-devel@lists.xen.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Boris Ostrovsky <boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, 
	Stefano Stabellini <sstabellini@kernel.org>, George Dunlap <george.dunlap@citrix.com>, 
	Ross Lagerwall <ross.lagerwall@citrix.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Wei Liu <wei.liu@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pdurrant@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=rmPFqplF;       spf=pass
 (google.com: domain of pdurrant@gmail.com designates 2607:f8b0:4864:20::444
 as permitted sender) smtp.mailfrom=pdurrant@gmail.com;       dmarc=pass
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

On Wed, 8 Jan 2020 at 15:21, Sergey Dyasli <sergey.dyasli@citrix.com> wrote:
>
> From: Ross Lagerwall <ross.lagerwall@citrix.com>
>
> When KASAN (or SLUB_DEBUG) is turned on, the normal expectation that
> allocations are aligned to the next power of 2 of the size does not
> hold. Therefore, handle grant copies that cross page boundaries.
>
> Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
> ---
> RFC --> v1:
> - Added BUILD_BUG_ON to the netback patch
> - xenvif_idx_release() now located outside the loop
>
> CC: Wei Liu <wei.liu@kernel.org>
> CC: Paul Durrant <paul@xen.org>
[snip]
>
> +static void __init __maybe_unused build_assertions(void)
> +{
> +       BUILD_BUG_ON(sizeof(struct xenvif_tx_cb) > 48);

FIELD_SIZEOF(struct sk_buff, cb) rather than a magic '48' I think.

  Paul

> +}
> +
>  MODULE_LICENSE("Dual BSD/GPL");
>  MODULE_ALIAS("xen-backend:vif");
> --
> 2.17.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACCGGhCGcdEq7CC3J0201ETvAd%2BPZ2fTDNUS3mo599Tuf-61yA%40mail.gmail.com.
