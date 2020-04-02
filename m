Return-Path: <kasan-dev+bncBAABBN5QSX2AKGQES76KFVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 59F0119BA9A
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 05:12:57 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id z9sf1519815pln.10
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 20:12:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585797176; cv=pass;
        d=google.com; s=arc-20160816;
        b=FKUtL6SNLurkEdZeJ0RCjDkkZjsY67LrF4tHTnMPUXXU3JYtq0l582PG9gzxx6Dmxf
         +aY6A4BqzvaYhlMqskpOh3e3Qymz2vKS2rF4VN3tja4duUGmCCZjIcxfx1frtVSuiObi
         S/KBWwU0Wb0C2D4Q52zKJ89mlEd+v4UXzSAsRSL8jNMOBO9HkLyuNX5Oe235eiAJXMdK
         lzlx3J8x22NVc1HKdRmYoFy1MkPcj04/gtsKqWl3eaZMsK3lqBG3f7WLPDSggq6vKdDF
         rIkIpGkz+XvC1DN+KpN8gPflLSmwjmPWZF8vyYWx7SYr6uUqWKDNpmn/UUSNBr/Ti850
         7xyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=qrc3ebsgnKMxz1i3gCaxQzHtGTEn4zFMHSj1iQwIXO4=;
        b=i2WkL+oYoFULqppDMZA+qx5UT7eelzm7zDTGOeL122ThhYWwP48JWUvBrTqt9Bc3GC
         EYw16sDfDbZ4iBOGniyWAPi4NPLVPkVcR6JSVyNruEpT9F3icae4qP36EZkBAxE9ORcP
         WAuy+npsYTYS78e24uZLYPDTvakGLh6HkBULeOFOdHzFIL7y0C6dNs7x379169YpbXaI
         WiSnJ68mfVeRBJMI5cGlGTariN6lkOLM0reCgJ9r9T4dSeY1Kh8Mdy7nzu5Dw7y0KtW7
         rbVKH0tB7aYGonN3zFBqpkC8R6O1j5l8WHRn4R4wlx0RxyBGuXcmbN6Wrew7Bo/h4VQl
         SuLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=S5Z4kCN3;
       spf=pass (google.com: domain of srs0=th+t=5s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Th+T=5S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qrc3ebsgnKMxz1i3gCaxQzHtGTEn4zFMHSj1iQwIXO4=;
        b=lwpB/RV+kZZ/mhYgN2glwEdwnCTFqSvJIubwZSs5oA5AyruZl1e0nzAz63sBAHakKy
         LWATh1MOsi8jD7MhzS1zzom8SvOkfyQ9F3grA21xLvxs27vbJKC3jXf6lpYEjw0rVYWI
         9/qf4c/m1/kBoN3+T2EqIb7+bxLoFgcj69oQ9juQZvmwjQXLIx9hcuNW8mW+bFPP4ruk
         lB1YynOHDXycQhJWug2+YfQY5SfeTFclcmp0vQkJC0rVIbBpClLsq5fXrtiCkRRgei2l
         7rCzQJTcrDG1i0d7osH7DaxUb+bKYmNp0aDSiUs/1jNE8MVIMycaJKhCOhsgxqIk750r
         S3oA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qrc3ebsgnKMxz1i3gCaxQzHtGTEn4zFMHSj1iQwIXO4=;
        b=l5nGQ+L0jVdxeeLpD5HgguvW3SlIOUbIGPE+12tEhl/Z327qhKFFE9f2n0ipPc7BT7
         tTWM7IxnV5lHQja0K02u3BpPVgKkAmsXGOl/+iC5wUmQOYWV8oJwRn6j3pEdWHkOjtMM
         z1Ii5TWXy1YMf1/WkRMZuzIgQOYqiHLZVUeeInmFr5DvsPXc7vgn7LBDeuZ5sddbto2p
         EQXmHC8Rm2b0tcKe2Ns8UMA+T6oh450/DCIcZpy8Kqy1QDiB4gpnhp/3AJhnPDH3FFOb
         Or01KDcJjuEgJXxbU2g0UbPs/qfV9I1FfGRf/JAsFG+vz2zY2IvlEzGV6hqa8tCqueTo
         8N9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubPnPpcPJhx5UwUmaJg2OPjLsR7QkZTMKNqvgCPs3Ud/l9Ido+L
	0ctA1jEXmObjPycU/+gz1pg=
X-Google-Smtp-Source: APiQypK8s/wq+76ByM6F7aj7twYbGXTmZEXhGbdZ7zyQQj+8yjO9JgosQucUDJs7BBrFSWPd05xXSA==
X-Received: by 2002:a17:902:7682:: with SMTP id m2mr893750pll.311.1585797175517;
        Wed, 01 Apr 2020 20:12:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:63:: with SMTP id 90ls1902657pla.10.gmail; Wed, 01
 Apr 2020 20:12:55 -0700 (PDT)
X-Received: by 2002:a17:902:8509:: with SMTP id bj9mr1020386plb.64.1585797175001;
        Wed, 01 Apr 2020 20:12:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585797174; cv=none;
        d=google.com; s=arc-20160816;
        b=IWmOSZsx/P0mZ89qPKrwwYMcBMEMCx42OFPNlJN1QK7P/Sv6ZrwYiH6pYkqRyxfvJW
         EiMm6nkGLSl48lD/MbszNNCWc4+Ao4unXzzhL2S6PYk72EMsyXr9hKIttpKbdliLCdYi
         /3iZpqvwbaZWO1OWuZiKtx1nGlLKRbC/oI7iHaoSySswQ8rfTjWZqeUGYgg19i70/0VF
         1vyCbOggveZ1cXbnlsRne2jyk0Xe2L5zZrlkkhAMRPVzemt/wo2LhI+p9xtaUsjf1foF
         0nqT/uWgdFgGLuREAXdrf/4Hp+eChxmq73Dh40pxqd6rWGGxSgDe8zN10Q3BXBP8OEaA
         8Q7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=9rV92NTLQf/tcpU3nEKZuyN2pshE1Ypm/5rg8SP3UbY=;
        b=hUQxZ+pbEWpp9+78jTv6HrLfr+qZtDo84RIm9K3xfqljBLevvzfisA1aVS+nNjktT6
         NAGoawx2rTIZZO9LCT8THFa/34ujcGGHO24qHv1PjtLYgF3dZa5gLgGJjnIssgibp0y8
         SnBfS4eD7D4UKmZtua6SPcIl8q6P/9GIRbjdocPi5uMg021XR14IDbKdjOxKlxM74/+A
         Xju1fVM1XhC+R0Bw6E+6vEUOOtDAvylcqet7o04W6hplk/g8ojnsyIbLEZtGX2S2J+D8
         UzqswAYfkP2lgj41LcInSTm26teMI97UyMDOgcISAldQ3vPv1rKEFMm1oJeXBPWBRll0
         zrTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=S5Z4kCN3;
       spf=pass (google.com: domain of srs0=th+t=5s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Th+T=5S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 74si221033pfy.0.2020.04.01.20.12.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Apr 2020 20:12:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=th+t=5s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 95FA0206D3;
	Thu,  2 Apr 2020 03:12:54 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 68B94352282A; Wed,  1 Apr 2020 20:12:54 -0700 (PDT)
Date: Wed, 1 Apr 2020 20:12:54 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Joe Perches <joe@perches.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>, dvyukov@google.com,
	glider@google.com, andreyknvl@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	apw@canonical.com, Will Deacon <will@kernel.org>
Subject: Re: [PATCH] checkpatch: Look for c99 comments in ctx_locate_comment
Message-ID: <20200402031254.GO19865@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200401101714.44781-1-elver@google.com>
 <9de4fb8fa1223fc61d6d8d8c41066eea3963c12e.camel@perches.com>
 <20200401153824.GX19865@paulmck-ThinkPad-P72>
 <65cb075435d2f385a53c77571b491b2b09faaf8e.camel@perches.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <65cb075435d2f385a53c77571b491b2b09faaf8e.camel@perches.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=S5Z4kCN3;       spf=pass
 (google.com: domain of srs0=th+t=5s=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Th+T=5S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, Apr 01, 2020 at 07:20:30PM -0700, Joe Perches wrote:
> Some checks look for comments around a specific function like
> read_barrier_depends.
> 
> Extend the check to support both c89 and c90 comment styles.
> 
> 	c89 /* comment */
> or
> 	c99 // comment
> 
> For c99 comments, only look a 3 single lines, the line being scanned,
> the line above and the line below the line being scanned rather than
> the patch diff context.
> 
> Signed-off-by: Joe Perches <joe@perches.com>

Tested-by: Paul E. McKenney <paulmck@kernel.org>

> ---
>  scripts/checkpatch.pl | 10 +++++++++-
>  1 file changed, 9 insertions(+), 1 deletion(-)
> 
> diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
> index d64c67..0f4db4 100755
> --- a/scripts/checkpatch.pl
> +++ b/scripts/checkpatch.pl
> @@ -1674,8 +1674,16 @@ sub ctx_statement_level {
>  sub ctx_locate_comment {
>  	my ($first_line, $end_line) = @_;
>  
> +	# If c99 comment on the current line, or the line before or after
> +	my ($current_comment) = ($rawlines[$end_line - 1] =~ m@^\+.*(//.*$)@);
> +	return $current_comment if (defined $current_comment);
> +	($current_comment) = ($rawlines[$end_line - 2] =~ m@^[\+ ].*(//.*$)@);
> +	return $current_comment if (defined $current_comment);
> +	($current_comment) = ($rawlines[$end_line] =~ m@^[\+ ].*(//.*$)@);
> +	return $current_comment if (defined $current_comment);
> +
>  	# Catch a comment on the end of the line itself.
> -	my ($current_comment) = ($rawlines[$end_line - 1] =~ m@.*(/\*.*\*/)\s*(?:\\\s*)?$@);
> +	($current_comment) = ($rawlines[$end_line - 1] =~ m@.*(/\*.*\*/)\s*(?:\\\s*)?$@);
>  	return $current_comment if (defined $current_comment);
>  
>  	# Look through the context and try and figure out if there is a
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200402031254.GO19865%40paulmck-ThinkPad-P72.
