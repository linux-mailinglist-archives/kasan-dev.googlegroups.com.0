Return-Path: <kasan-dev+bncBDAZZCVNSYPBBOO3SH2AKGQEZM77THA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2141719A99A
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Apr 2020 12:32:27 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id d10sf4694336pjz.5
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 03:32:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585737145; cv=pass;
        d=google.com; s=arc-20160816;
        b=SG00GL6MiC88Vs6EsGLpA9s2heTn1ImU77nR20L2ZAIG6DUQGL6yVn8cNjRrY7UADk
         f57JfnW8xQUVA+GMrIqO7oRl3JC95VF1qLtNZq0glOgfXWvL6PBbeqkDotdeLGd+gCqE
         P82kwaGdEADD4/qWUBNhrJJHuURyrjkCEm/OnB3+FjLNll1kwzU5coIpmCfIoq9VaQKq
         LM9+aAznJZNTTmVK6m4XcT69Z+xQXcYWKcT9Uj96PitmDs+xAwNQiVw6j2TlFC7136qK
         /se5ECsjrZomL/1ySEy0l+KLhJ726jwjzd5JWm/Y4UORTVUtwtuM7F48ghotoQY8Gl2O
         GNXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=wSMeWAMvsu3zZNmdEeef0BFWVwAVy2aLG0q9GkZPjUo=;
        b=1DBwqny0NPZsSJxSWKENYlL2jeHVamMPyPT7HMq7gjbfWswwGdLfHG4BKRC4z1Sakx
         NCBCoQWnxXfFyecEekM13BcwagT8drlGTvExx6LvggCvKphITX0Tiz+ePJLwWZU7awKQ
         i5EDEmlcI4UNZJgqDq2658dIwsrbQwZ8cWmHP6zQR+SOXkZI+My6red1ldfwvVE8wWff
         /Ejm+igtK+TJl8VACablc/gRHcJGiySBCRc2wdeBRrz0E7YVLbxM8YBuNVNfW76Xzajh
         OTlNMWos7teQKJRnVdgmwuHNDD1gEz+0juWesExDvKeAmsUgtEr7JnUvSFaYDXdu0zIW
         R3+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=j4j28szC;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wSMeWAMvsu3zZNmdEeef0BFWVwAVy2aLG0q9GkZPjUo=;
        b=e6QVc1YaiIUOthWavCrTPM9sq3MQ6RwuMn0GvTPZXzMt4gC1cXmLoFyw9gnONj75QC
         XkYN/oKk1Q3z8Jb+3tAAVGGtqRUbfcCpPgSnrcpQ+rLSYUUuAuvc+6aEq8s5LPdOdIRy
         y8KAokXv0srNm0AtRFWzz0MeB4WgnwDAYIT+ynlTYoIQCMm99N7hCh//V9fslMnfEKlX
         hixF6s+hfHUv/COFXmiN79LOsuasSuIFJq9tl6GtyArhRyTIPtvJA8STSOEIl7JC1dPl
         gaKMRgeIVzsuBaggid0TXmmdGkXa70hPbBiDLY4f6H6rLOs0wo1m2fWBvqTLdchflr7T
         NvNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wSMeWAMvsu3zZNmdEeef0BFWVwAVy2aLG0q9GkZPjUo=;
        b=q1L67ikttrXUXDe3eUdaEYGFQtCtn2SHvcDu7VLf8dxZCpgR5S6aCtp06lcU/LTK9I
         VV6p0GR729HTjuZUJVjdh0r1FpkpTTVef8P6Q3FhUhxLSZzRPOH1e6m1SOqDqcjufs/1
         dq17dhHWOTPDKMw4WnI1SSSaMQFHGy7lQUh64iINCCVOGvIcinIlll6IvUo3Wp3Yh5bL
         3Yy+B1PGOq3SMwvLa31K0A+fRtXGwedhlixDe9D01itHBH4IUFHzsGxQgip5oyfcfLHD
         O5+zJx53SW/Ljj1lTUsd/p44njNsZsYqQeEIAQUZ5aSQU94Wimd7kPpUTSa6RYDW+ZHx
         lVyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3fO+aTaxhF6u3UF8edPGU0tkKZwb1OFxuP7RWg+QnTD+6KwmDi
	O84dAEeMOgEOObr+NtRp5hY=
X-Google-Smtp-Source: ADFU+vu3lextaY6g7Anl/aW0V8I3WBXkqrGWpMg4vKNPXYXfPYNtFD18MMB2A+ww0h9RsmtUES0EjA==
X-Received: by 2002:a17:902:8d8d:: with SMTP id v13mr22155307plo.260.1585737145447;
        Wed, 01 Apr 2020 03:32:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:332a:: with SMTP id m39ls4293975pjb.2.gmail; Wed, 01
 Apr 2020 03:32:25 -0700 (PDT)
X-Received: by 2002:a17:902:9308:: with SMTP id bc8mr22349332plb.278.1585737145001;
        Wed, 01 Apr 2020 03:32:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585737144; cv=none;
        d=google.com; s=arc-20160816;
        b=drcJY1CzAoAdRslFYevpX1BANhHUS9LUDv5V+bmEiIp52wz7OjGRWHQxs6uEngUy5v
         URmkEr+5D5+6n1aZHl9RpM3Fs40t8YSWTW+nYZkL4emEHKfiIUijI7sFy0btOhL7jnnA
         aALJ4tj8NlBQgCb7JU1q0vzktGnpJxYBnicmjNO/Gr4XV4U/ffCEPYtCwL7fYJj7jAbM
         r+DMb7jzhtU+3JUBUPxp41/CY9XwDoecIWxqyhifhrRLUxYibTSODFAVdlVgHIjRnWt/
         YrFY+zUL6hZNfaJV4dcjS9BxPr50t8UfaXVSMVjAj0Ncmjw3hiDmNt9ZUdcwC2H/ZkAy
         LH8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=zWcdVpcxD/Dk+OqvT8zl0qrNeXb+MTKqnvJtFLuy3DU=;
        b=cLOpRBHS0RdKjuGri6vJel0QaUn1CJHJvUEjGw3RDl0Nnh9gDi7C6+gUz6Cu7ThGKS
         vb1e6/N2TkW+KW0yCm+IslRUGPA9QddYygSy6sRHI/EUqSVj6cMQMKBvQdglMMYu1Xog
         JtVMlQFdI4riCfnxIOrFBW96Oq34TvMmU4A1yOWV4hWsacugSjm9XTtrUwDf067Az51N
         e/QFE6nJqkEsWW1WZ9stRZdrv9IFjvNOu9aMZ4TDxxrjb3nVHcnY0RHoSaIjs7hniP5K
         /AAHBDLq0sH2K6PtPAdC1119MCdfp8xQ4Wekc0GlS7el6yEIcbnMk6hbB7m+SzJgZhAZ
         t+3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=j4j28szC;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c207si71340pfc.3.2020.04.01.03.32.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Apr 2020 03:32:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2EAEA20772;
	Wed,  1 Apr 2020 10:32:23 +0000 (UTC)
Date: Wed, 1 Apr 2020 11:32:20 +0100
From: Will Deacon <will@kernel.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, apw@canonical.com, joe@perches.com
Subject: Re: [PATCH] checkpatch: Warn about data_race() without comment
Message-ID: <20200401103219.GB17575@willie-the-truck>
References: <20200401101714.44781-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200401101714.44781-1-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=j4j28szC;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, Apr 01, 2020 at 12:17:14PM +0200, Marco Elver wrote:
> Warn about applications of data_race() without a comment, to encourage
> documenting the reasoning behind why it was deemed safe.
> 
> Suggested-by: Will Deacon <will@kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  scripts/checkpatch.pl | 8 ++++++++
>  1 file changed, 8 insertions(+)
> 
> diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
> index a63380c6b0d2..48bb9508e300 100755
> --- a/scripts/checkpatch.pl
> +++ b/scripts/checkpatch.pl
> @@ -5833,6 +5833,14 @@ sub process {
>  			}
>  		}
>  
> +# check for data_race without a comment.
> +		if ($line =~ /\bdata_race\s*\(/) {
> +			if (!ctx_has_comment($first_line, $linenr)) {
> +				WARN("DATA_RACE",
> +				     "data_race without comment\n" . $herecurr);
> +			}
> +		}
> +

Thanks, looks sane to me:

Acked-by: Will Deacon <will@kernel.org>

Although I suppose I now need to add some comments to my list stuff. I
didn't think that through, did I? ;)

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200401103219.GB17575%40willie-the-truck.
