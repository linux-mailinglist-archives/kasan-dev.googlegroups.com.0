Return-Path: <kasan-dev+bncBCXO5E6EQQFBBXE4WSYAMGQEFO5E6PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id D95958967B3
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 10:07:58 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1deed404fd7sf1875535ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 01:07:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712131677; cv=pass;
        d=google.com; s=arc-20160816;
        b=d9znLfZnAO+1gGjq6EFkIIeOBmsXn1MltXMQYARoV+nuvBI90G8boVgjJftsRA162U
         cZCriB4iVsoV2oIUfNyKU/rS8yxcD8G5enr+7nAuD+WwRRGH6WnQYlyTsra38n38I33s
         BL84SrgA35YGE+owvvRR97xsLtEuZ+GLb16uUoFBnfy/TBt98EK3nkP8aiLx53SVXZxJ
         OrpbPSRBbPaedneMtsUbSl+7B5Z/sdV+67Wt/XAvTWTMubR+A9p2SJqJcPI/OzqXmZ/v
         qmw8t4xG+I1kULbpg/NjJ+C0TMd9pH7UoixyozmZHYD9WAhiBxBDMtn24O3+LdNnXPl0
         UpnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yiCZzUPYhtKxOq0KtKiIu3E6BG+5Rgecz/8OYULHoO0=;
        fh=f2+u014vA+wzBteQAv28MTTR9mkN/CJT+LPf5sN6OgM=;
        b=eH9NNR4hZd+0SQ81nqAMnigQxIBA+fGPxPAqpsZ2QddLKftEMhOOpcCUrliqaimzTd
         bKMO75+8YtSeyRgTze1BfNCyEdEJUM1xxHuKlsBDywji3UHS/c8cIGR71pYx43aOrTnD
         Md5LWWw/XPdSbW73XRrrlPxTZNoalpjta4sq7PRiHtxBtNJWbkJgIQLvCtjQNT9q/hYM
         PN+1Nunx8DBvK47VJ5mmx20hW6FAfdIMN2AOLG4LVeqT/8jPGfJwga91KD+Cr6BhGYwi
         V9yX9oJipjJPbPh2reG82oP2ws+wBHgFIwm5SLoCNwL1ME6Gfmx0IM0Kgxh8BA1BWVdQ
         Ufqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iIwfgNho;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712131677; x=1712736477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yiCZzUPYhtKxOq0KtKiIu3E6BG+5Rgecz/8OYULHoO0=;
        b=sV9yhWAjAJIupQSKEZ2lINEovGfNaacgi3LyVmEFsxj4VIpAQOo0KApK0PK5bMTSjf
         WC65XqgkLXXA/+8HJ31fgIGU8qAfBd7ZS7U/PMTG1Q+tYkY9bZ6mvnKEWAD7rMbdHqps
         511NAn3uDYG7ReVML92AxZI7MzMhmeqJV/Y/wP9PAUiKSzgcbEWgfoEzc9dW7CVYaXM1
         7CNItniUzNRdU27+goBJFHKVdDy2/+EicK9ESZ32GkMhJfZExXB7NZCRcyL1IymTIMV+
         o4npDoHlQl1DuG4pnfIOxeefAZQhHftS/kO7qELp9qZmLBbmsE+HIxkV9ZKeVYiZXuT6
         Xs+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712131677; x=1712736477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yiCZzUPYhtKxOq0KtKiIu3E6BG+5Rgecz/8OYULHoO0=;
        b=RpByEN/DqofeZi6jZM2XAwZIeK7obWnqoxYVPO5wXudD4sNQmvq2J7tRCvwfYlUlaD
         QQLwHYPYK2/3r056/Kd/3vhrvxuvF4KH1/FyzJXQ0tmDPU5saMg1faxZdntIGzHdP7kD
         /XXGKlUMeOruoyThcB4ljt9tuf5KtzlzH8TxNluSWwne48pO5Wf1JujFAUGPiJxShYeH
         2j0uzN2IxYG01xwUo5dZ6d8xKaYTPgG7Q9wjXqQkgdK1Lu51hlaAvVijmC7suaB6dgGE
         ynemdqJg2hPDFHfu28aIksjSUoERtmTdAEOA0suLG7ljZ6Vl3CIyr9hcTzBvZgaW3mlf
         jQzw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVQXV0Li7T4l8LQiI4rxnBlz5Q3T/L2QIy0rX7H2UnrJul4jVgB4+F3NiKCnJnYYF1IyIf3VLjIdrDfcrID3gYhprTiX6QI+w==
X-Gm-Message-State: AOJu0YwlnrVir9yLhw/hgcGzIoKEhMv9mV9TiIAPbhcoixb/r/5Lw2GF
	LPTFdAA8VN6wakMDTZNQTf/Q4HeK5fMFaDFYIqNlT1wQ6Nqifim9
X-Google-Smtp-Source: AGHT+IH+UR3K/sZ+1bOs8P8BWHC1EwPbwVpe1MSXl+TVIUA1exbcnk6TzM9AaEbe+UM5nQGQfToS0g==
X-Received: by 2002:a17:902:e747:b0:1e0:a8b8:abbd with SMTP id p7-20020a170902e74700b001e0a8b8abbdmr181736plf.28.1712131677152;
        Wed, 03 Apr 2024 01:07:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f707:b0:1e2:408c:6e07 with SMTP id
 h7-20020a170902f70700b001e2408c6e07ls3241194plo.2.-pod-prod-03-us; Wed, 03
 Apr 2024 01:07:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV+OVYkCRhpDN79cQrqCSIUIeqvXrByahbykTVf5XDziGY/bHIxmXptYScGEpuxkHEPPx406kApUMCb7fccXOjQi8ZBrfhnoyWG6g==
X-Received: by 2002:a17:903:32c8:b0:1e0:1bff:59e2 with SMTP id i8-20020a17090332c800b001e01bff59e2mr2174514plr.39.1712131675963;
        Wed, 03 Apr 2024 01:07:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712131675; cv=none;
        d=google.com; s=arc-20160816;
        b=jvQumtEtiBep220cXqK4nAKUTN+d5q6yiuXQRYyXzuidkXMiFk+eH6XgeU/NptjmiN
         nr+aSoQxY1LQkm/+CHtmIESyu1nzVz8TqL5nFEEcRcJGBeQMadMBNAjK6sMhVfDJDo79
         zZ2kwuW12U5usp0ut3M6D+wtQjPLWi8ixxK3+iG5aDFXiM66Kt4MfWiiAHa2mN78CJuL
         mgDSPTpX2mRlsTDSRejoBjbD4GKncvz+sGH1WjcHs4Vb4TBhdtrmLUge5ZQMNKefm6L7
         NTk97aKGrJtrDX8ADKm6ozdZSuASDp+7hT5Wfr/1SH83oeRrark15/M2HV+vf8r/PmJB
         he+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wS8aunKc914gsO8OADe2RcO/iLEQH9sIrTWO+PuySLU=;
        fh=K69ocErNoUG73TSKqQPkP/HXNoZuhXzISvTGr5ELyyg=;
        b=FD88o7ojHxnM5eNr1xVvofsmNwJezHNTA3X1pvbGHcDOEsAqigM+c9vLdevCUGMJBy
         vBOWvwAEKPVFtRatSc78AtxOp01Vx0TGPkOIBch0bwxZgwcKFVuQKBX6NMhcuBsRhHAG
         FjAscZcPMJutibWDnChVmd0AIf9kz14jlh2dgEAtLOVbYVmyf274Io+qeGSBRje6t7xI
         u0zIYEMO5bSyGKtv+/1PcpO9VCIxjhvfxQYmoMXWQdRNTGk5/8pIanjhpQwdN1l6ZBIy
         DlcvxMzFAnfVz3PJEWMjvw9yx60yfObte2U1Hg7VpIHUH9rjndROIrWCgADILbYxTVDz
         aHtA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iIwfgNho;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id kr14-20020a170903080e00b001defa30ea2bsi788073plb.9.2024.04.03.01.07.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 01:07:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 16871CE0B3F;
	Wed,  3 Apr 2024 08:07:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2C107C43330;
	Wed,  3 Apr 2024 08:07:50 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: linux-kernel@vger.kernel.org,
	Kees Cook <keescook@chromium.org>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org
Subject: [PATCH 02/34] ubsan: fix unused variable warning in test module
Date: Wed,  3 Apr 2024 10:06:20 +0200
Message-Id: <20240403080702.3509288-3-arnd@kernel.org>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240403080702.3509288-1-arnd@kernel.org>
References: <20240403080702.3509288-1-arnd@kernel.org>
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iIwfgNho;       spf=pass
 (google.com: domain of arnd@kernel.org designates 2604:1380:40e1:4800::1 as
 permitted sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Arnd Bergmann <arnd@arndb.de>

This is one of the drivers with an unused variable that is marked 'const'.
Adding a __used annotation here avoids the warning and lets us enable
the option by default:

lib/test_ubsan.c:137:28: error: unused variable 'skip_ubsan_array' [-Werror,-Wunused-const-variable]

Fixes: 4a26f49b7b3d ("ubsan: expand tests and reporting")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 lib/test_ubsan.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
index 276c12140ee2..c288df9372ed 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -134,7 +134,7 @@ static const test_ubsan_fp test_ubsan_array[] = {
 };
 
 /* Excluded because they Oops the module. */
-static const test_ubsan_fp skip_ubsan_array[] = {
+static __used const test_ubsan_fp skip_ubsan_array[] = {
 	test_ubsan_divrem_overflow,
 };
 
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240403080702.3509288-3-arnd%40kernel.org.
