Return-Path: <kasan-dev+bncBDY3NC743AGBBF7CSL2AKGQEH7ITAVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C59019AEA1
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Apr 2020 17:19:52 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id l137sf168295oih.21
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 08:19:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585754391; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZSZmXw45SqPQHa2AlwhfyhzawyjcVNTcHuQFu6b/bmOhSzzPA3t30k56UqV1f1a6gB
         oQwg6HwlnF/LAx9FRjiQFkrqqQW3uzrhVflov77pQSWubAo/50Hi8bGWSl9V2NkFf8EK
         OCNqws51c2pcdIyZMVVAGdqjwc5ic83Ufzgu3NuMAVzbf1Tlre2C25Y2QRxJBp2wkz1F
         bvpXLgwWHO79+fiikEKWBMS3ESKbOjYH+AXLhqFi2sOURfL6uJrp5IzEMqsm3ipAQxOt
         gIAXVf08zvy7ITgb+AikJsIxL645FDmhC3rnL4aoLWy80gZhKia9hWOC/fofGnYhI7Az
         fCXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=TT39H5LBQ02Wp86GfRd087oq6T2r3AoQYqxSj3SEjM4=;
        b=V+H6IsIH0v15eR4FD0J+Y2auU7ARj/O1hYgE7C5GBX1QwK+1LNzXsSe/B0131uH9Ia
         +AeZQGYutBVEpr5x8gtxA9j77iQx+khmSftIrJv4l0lZX+UG5xNTPnYJHRBit7Hen3Gm
         nJv+GP5NPkEXp+DkoTKBydgPMMjpul6DK4UHoAQZVEXKfIk3s850oHK43QVtMD9YPn4y
         XA1vQ3/BKvBP03gAOWE07HsxetXvc/FCcW8A3L++thbGaPAenqO8l6GqUDmeULmM4V4k
         WGH/aWaD19dvNCq554WA8/JDnHMUcxcsOonOpEwNM+XqmH2CiTlRVj5NxzVQ/YnjBYa4
         2ZSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.79 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TT39H5LBQ02Wp86GfRd087oq6T2r3AoQYqxSj3SEjM4=;
        b=aUdzWKwwdH8IaLWXgE8ORq0mfAuEDG8oZud4uh9kLDdVDeV2/NQVptXzyp4M+JWnX2
         vLyNBpls77gIPLen8XaJG5+7Rw2GjFiFysRDIhs0qvEHOUAtxo1r3qXJ8yS35D/+PXjr
         gTfQXs5VcqISBTJn8L6FmswOD++dc146d0E1q7V94T7YTa3E6+BsIaJNsuxrsxdBmxkr
         LJt7xjKkuVwgLf7tKFcWVByGp8jhogSpX0tyDUcqxfvbShpujlAq65A/MscvJ1tdzloj
         OVYOej+cXSrb9bENYymAoRSHlzWYDaZfiN6t/uJyHDmL2i5LHm2N5mZfcgahi4BvL0Ww
         iiow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TT39H5LBQ02Wp86GfRd087oq6T2r3AoQYqxSj3SEjM4=;
        b=tnA6nBNP1OL1i2OktXyi71ZgVsdy3BukkhVlGXkYks6gnTM2pTCyd5AsEtHidxHg+a
         8Ry36yQ3siG2YQ6z4C83oaV9CguXyiMv1EvCUeHhkX9COOw9ZJEm4HobX/7NOheIQEUY
         XFWA7d578+phbukHNdPpPZx1pffSvZYnT5Z826N4GS6X94BxJtx5E6feofcxokb/QMul
         HUjtQvRYNduAebWU7qQo+kDg9KeFnHTTbSPOAWmkxQsDDlOHvzo7PZp9d370EVaODRDe
         yeFlFaJeoTtpZJtdNi41uD+Ij647c9bvVvOLo3o7eZYfKooQLdHYxVGWeNhySviI8UL6
         4G2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1cwHZjTL+PwidsWWVgTIYMLUuEFirwV6gapzqhNOBu37/IehMW
	zGIO8+bqE7D61YDqbD43Ztg=
X-Google-Smtp-Source: ADFU+vsLhlN9dTasYmxMtx4rd0TRGl6C8v5OpHeQgvhQXTl6CHALu8Ui3aoZwsMslAcZkBLPF5JYaA==
X-Received: by 2002:a9d:6c8f:: with SMTP id c15mr7059916otr.10.1585754391404;
        Wed, 01 Apr 2020 08:19:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:49cc:: with SMTP id w195ls9986583oia.10.gmail; Wed, 01
 Apr 2020 08:19:51 -0700 (PDT)
X-Received: by 2002:aca:47c8:: with SMTP id u191mr3235916oia.17.1585754390996;
        Wed, 01 Apr 2020 08:19:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585754390; cv=none;
        d=google.com; s=arc-20160816;
        b=y+Bdd6/6sIvLyOWrk28Gnv0w4R3XBOwkM6OYQCMvbooBALeP9iPwCyAyuJPwrmjiqW
         XElkcWIeDVjgT7K02g1Os8OGyNB2TKqoaDs1uaRUjgD1sEU/DF4HsiNLwZKBc5kDydRS
         iBMOBYf+ySkPZDuLHvpaTy9OwQTptJnvAMcDTptz8vGwzx4uJf5dXSU1lHWZ9F65kZGM
         fgiw1D8HsnLGiw9wdG+BE8HPhiraqmbic2FAG26HHlH1iqlX7NIsJN0pO9BzXN5EnGhF
         lZY83llBuKmlOGG40ID/f5fez9EGFrPVziMJLOP0sA1SfYmB4vifmVprNV3FurU2KJDP
         Hz+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=1XnlZVbpr1U2aKUVKaFeVyI4AWjGSHtmWhCDkjN1TsQ=;
        b=q76QZ6bvgLzhcE+HXRqRsKAX4LvHA5KqyY4Lt6/eRQJvtmYbUFG+wcf4Y3biiFeFOf
         Ihg7v7ZFrd8QfTxy9ba26WQE/E+wlAKmFl5OXQBr5oKjD4IyiakGphPBPDn7zPLozF3K
         +hbO+oHk6jugOsHi/yhy/OnqZkEBF9msjJSOs5kif0yDNYvrp66G2Rzf6A8eDVfVhgSr
         IvcVVSIYqKQMGo5fafO/bQYV1dfplefZWIPWMti8p17VqoLt+mUbQnNRAqycwYND+jJt
         zMVATGhFtNbZhFUBaqL9WbCm/hBXp5+mocLutE8vPkHiq7j4y5z5QXfeP7QSqDQyw5ni
         Ddlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.79 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from smtprelay.hostedemail.com (smtprelay0079.hostedemail.com. [216.40.44.79])
        by gmr-mx.google.com with ESMTPS id n5si212863otf.3.2020.04.01.08.19.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Apr 2020 08:19:50 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.79 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.79;
Received: from filter.hostedemail.com (clb03-v110.bra.tucows.net [216.40.38.60])
	by smtprelay05.hostedemail.com (Postfix) with ESMTP id E5210180238C3;
	Wed,  1 Apr 2020 15:19:49 +0000 (UTC)
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Spam-Summary: 2,0,0,,d41d8cd98f00b204,joe@perches.com,,RULES_HIT:41:355:379:599:973:982:988:989:1260:1277:1311:1313:1314:1345:1359:1437:1515:1516:1518:1534:1541:1593:1594:1711:1730:1747:1777:1792:2194:2199:2393:2559:2562:2828:2895:3138:3139:3140:3141:3142:3352:3622:3865:3866:3867:3868:3872:3874:4250:4321:5007:6119:7550:7903:10004:10400:10848:11026:11232:11473:11658:11914:12043:12296:12297:12438:12679:12740:12760:12895:13069:13095:13311:13357:13439:14181:14659:14721:21080:21433:21451:21627:30054:30070:30091,0,RBL:none,CacheIP:none,Bayesian:0.5,0.5,0.5,Netcheck:none,DomainCache:0,MSF:not bulk,SPF:,MSBL:0,DNSBL:none,Custom_rules:0:0:0,LFtime:1,LUA_SUMMARY:none
X-HE-Tag: plane54_3880c5014bc02
X-Filterd-Recvd-Size: 2018
Received: from XPS-9350.home (unknown [47.151.136.130])
	(Authenticated sender: joe@perches.com)
	by omf01.hostedemail.com (Postfix) with ESMTPA;
	Wed,  1 Apr 2020 15:19:48 +0000 (UTC)
Message-ID: <9de4fb8fa1223fc61d6d8d8c41066eea3963c12e.camel@perches.com>
Subject: Re: [PATCH] checkpatch: Warn about data_race() without comment
From: Joe Perches <joe@perches.com>
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
 andreyknvl@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,  apw@canonical.com, Will Deacon
 <will@kernel.org>
Date: Wed, 01 Apr 2020 08:17:52 -0700
In-Reply-To: <20200401101714.44781-1-elver@google.com>
References: <20200401101714.44781-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.1-2
MIME-Version: 1.0
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.79 is neither permitted nor denied by best guess
 record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
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

On Wed, 2020-04-01 at 12:17 +0200, Marco Elver wrote:
> Warn about applications of data_race() without a comment, to encourage
> documenting the reasoning behind why it was deemed safe.
[]
> diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
[]
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
>  # check for smp_read_barrier_depends and read_barrier_depends
>  		if (!$file && $line =~ /\b(smp_|)read_barrier_depends\s*\(/) {
>  			WARN("READ_BARRIER_DEPENDS",

Sensible enough but it looks like ctx_has_comment should
be updated to allow c99 comments too, but that should be
a separate change from this patch.

Otherwise, this style emits a message:

WARNING: data_race without comment
#135: FILE: kernel/rcu/tasks.h:135:
+	int i = data_race(rtp->gp_state); // Let KCSAN detect update races

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9de4fb8fa1223fc61d6d8d8c41066eea3963c12e.camel%40perches.com.
