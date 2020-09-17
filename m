Return-Path: <kasan-dev+bncBDDL3KWR4EBRBNFOR35QKGQEVTRVHHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 1062C26E1AA
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 19:04:54 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id c8sf2130326ila.20
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:04:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600362293; cv=pass;
        d=google.com; s=arc-20160816;
        b=CaaTfhkE6b8ZCDSDqthSKG+YQWktNJ92/Ag8/l+b/eWWQCpcItqrR8aQl77d1e+08/
         nPG79VNLG4wF88FDUCVXyAvt4y01ZS7I7kBQpjdtgXQgQF8Z2gBDJLtwhCE1vZFXYlUf
         t7k8mIyi3Le00WL0vvIC1H2bKJnxfpcCfzcFJsWWda4/HxCq+ous7AX2dLGaUtCXkXgB
         NoohbOOYZ7lpIRp4Jvl8YanGZjQaJoQX0XvQuLUFAmjx5BtfBcXNrVpiIc66ALkwXJ/n
         G02bsBoETouzWpoq9hKuiPfGz3j/nggU8H9pyZVez2tB5cugAsujjletGXxyamg85KTg
         e/cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=gY+OvJDJkYRLf3Hi6Es19AShWRd+WjUPSXI4NSPMBHA=;
        b=pM4dBvnOVFxOKKUhFoxeNUHCMspGwuQRc54/ScGZrUPnLJTQgqUj+ugXiGgQO/zpW+
         VhjgJjNh8WY9CdvQvsHykdMQ6ffyzJelKGFeoanJDga76HESs1tkhp1Tk77T8hpeIjyP
         mwT2YtAnqVgkul3N43hiFI0iCblELzSYVUnrbzd4MPJ+q+3QPyMaP+cPsJAOs/m2Gg3I
         TDZElcORMf459DUlf6Ttf8xN/JM6emcBgc1TiCjXb4RleTV5lQycE6Lzb/YxK/4cbBiZ
         lgwyZDcQQ4U/Vi/lGI8ykORsKXTEzKxjJ0npvFJQ7tTNuRVuGmD6N8bufIG+nN65kI92
         nxWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gY+OvJDJkYRLf3Hi6Es19AShWRd+WjUPSXI4NSPMBHA=;
        b=jaeuMmETA6MGakRY0QGrGq4QVxRaN2UorcTnXJ1v6YpTU9TCmK8Qj9B2G28COSVRZb
         usyhscM5TaZECt557gDR9cdkDxczCyl2otqcdnNpWB+IRcDifq72JHV0JuSicMBh0b9V
         LeDHG4dAupFdYpq4ut6XioJWe2pai1cqK9Y2XUTeyCDojLCFh77Ss88NWuvUyxDP8nVb
         q9lL6Noo693E4zqPt6ZuJooFo+7XszOMmXO85vKZybSPKoNYu17FtJq3XVU49PtYaepb
         ElzKtKixZYhznW0Amtijb52n5XT7bU+YcqiAJ2+74is56jyrf2i+SJTFGZNuFVaAMzdr
         FpWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gY+OvJDJkYRLf3Hi6Es19AShWRd+WjUPSXI4NSPMBHA=;
        b=EIVfH6jyZWDt5ZS9zJd1PIITL7poxB75pnI2SkqhK7S7K9YFV22tVcyQ0dm/K7tKYz
         K5ct+jx64XC49ojsyIbwJB3YcZA+FfCPavfdjWgzDDFDao4KaL7oBAmEVh5MDRKtxs7W
         bVFmCKdenIOprThQ8QeClXGxbWEPJcs9k0uoNTTr8xZSftPn6epGYoxKpoC2qK8IyEOB
         y55E8TjFMRPnc/6d3aAiQ79NfdES9tYciO6ddCcyBXuccyhkvK/+trMYupb10mhZrKPq
         BdCF37g2ZFml0nPbf6AudNt7miVxMCBsdZHsT7aGLo6ms7ik/2uynuu5i4H0Ss7NvJ2n
         Nqdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533NMMWnvHD4bnaWcFRwUGvvAQpnCvl5WvuxiyXhxXXaS7uJ0dCY
	j9fXOxJa/QQSoajF1x7yO/c=
X-Google-Smtp-Source: ABdhPJw9vjrJG3Hf1wCzBBnDIM/SOnHFYgdd0VZAhUhnUZ9QcugZ6yUZsoYvpCEq2IOj39xiYocmuw==
X-Received: by 2002:a92:710c:: with SMTP id m12mr8034989ilc.217.1600362292980;
        Thu, 17 Sep 2020 10:04:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:70c5:: with SMTP id f188ls357236jac.3.gmail; Thu, 17 Sep
 2020 10:04:52 -0700 (PDT)
X-Received: by 2002:a02:a498:: with SMTP id d24mr27729736jam.137.1600362292441;
        Thu, 17 Sep 2020 10:04:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600362292; cv=none;
        d=google.com; s=arc-20160816;
        b=Kn6Z9sV5HMDHvjevYQmfu/MgxJjv+IC7r5jd7aoiDtBmVL6uot0KTdhpoUm5Nj6hk4
         /m6mOnJfzVAcM06Kaij6YP6xCubSbmb9eSwIjKOlMcGS/M7/IhXHWi/3GOUtD72JjJhS
         +M4rpxB0nIFY8FtqrSg6VQRDqOZ9B4OyO/RRj4u1Axy3q//cc/pysfLY0YEQIjDLqInG
         SLW2WY3do+Kxfkur9HYiwi7rU9I2IS/DB/PBZ/gYTF8NdAFnYQGlucD359Dk8VHR6Z+6
         2Jy5x3q+0uy3S5zd+MlJ53R72YZsXfV56oe5vbjf1ggWtfRkbpKIzOJNsuu0vsC9ncpW
         ARRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=S6uLOhttHu5NfUBVVORPoyqJx05TO1H0hFXYZuFnSrI=;
        b=neaCCHs3c/UbZIpRmHRUhW76fGcHIyZn+55EADMfOuct29T4fZX3yE7WePu8M/rn2+
         mMTqXx5Qmex7hq0B2KUFfXNq3SPd0Ti1xLa8+iHwpt3yeH0tK+oNcVCh+7NwvWfon8sb
         cOiOeCkLC4Xjf0jNF3ovSLLgbspUNSWZ9wtrQ6MFgjnk11NDG7K80hgByP58zOel+mX7
         I3LdmEPbfESYzvfeFeSNtGVEjle6zj35falKZnAJhZ9NB/rdQsUrAzToJkZMtpV0O92H
         Vx9VUpP8JTydQIOkV/tQ4zSsIvm+KdJ2oanRrqEyC0GJgb5WC3xdYGyvVUJu30bw7Ma+
         gCkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s185si22328ilc.0.2020.09.17.10.04.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 10:04:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 27D50206CA;
	Thu, 17 Sep 2020 17:04:49 +0000 (UTC)
Date: Thu, 17 Sep 2020 18:04:46 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 36/37] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
Message-ID: <20200917170446.GJ10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <d5705790ba42513fdc302f679bf420cf86fbadb6.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d5705790ba42513fdc302f679bf420cf86fbadb6.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 15, 2020 at 11:16:18PM +0200, Andrey Konovalov wrote:
> Hardware tag-based KASAN is now ready, enable the configuration option.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917170446.GJ10662%40gaia.
