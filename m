Return-Path: <kasan-dev+bncBDKMZTOATIBRBHUU627AMGQEDYVYQEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id E7023A6BE8E
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 16:47:44 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5484ea884f2sf1097832e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 08:47:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742572064; cv=pass;
        d=google.com; s=arc-20240605;
        b=JWQ5eq6Haytnw5HWmbUPc0upKZhjTxYjQdKcVZvWdtmGMG4fRApsJ8c3UCsBec82gN
         QWCwf5QQa/4tKo2VDPHLwGXYAsKgrt00FiWx+FDr1Mh5pC28tpabeIcDygoKLFT5sM7S
         A3bHvqPlQTsx6N3qtJZfEbM/Sgk+JqzpGE+99n/jSxQdk9pi2BGWfPkcxJGPO9cfkbRj
         wv+yqF0zL4sAJbjvRrB41+4BimqjGtIETGoct9CfJg2+p83xJZ9IhWljO4US8dmUHFXp
         mO1qBYcemq887tUyFDRqb9OVBmVkrZhIPzrnvxJThR9zTJgj/UpE5IxUnJWDGN35CHeY
         qnzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:to:from:date:sender:dkim-signature;
        bh=LvHsLJh9Ue19EozP5MpThFocihOP4dkIv3j8EewJmQI=;
        fh=xAi0ZX/Ve8VyNw7HrbjpR53PM+PcDpf73pGCAxWOxJI=;
        b=Av2LrJDhFcqNvGi4/I8ENAqo/vFJVsAexMO8RvfpiLmFb68Af2NYHd4+Gw790IL+Qu
         94qFFolGGBTSG8/Fep9lfEV/HmWmD2W8omikdIKW8TSXwtQHczdVA+WXqJ8c5BrEsvmw
         KrZGAFwNNJnXKjEarXbVPCWiXrNk8Iq5Au81fgN5Py7URMhd2Zlf0Cv4OF6QnoFyywDW
         mykLQkEDr1MEYnHDtzipwHDTNgbOSCcqV8nykxSDkacEwUMNsQHK0u5b2DfdIlL/YXht
         oI0HQxd+VYykocx8JLrgZT+jR17f1QLxWzHujn/mm6VmWPjo2SVuIVDEanEvA/mU+K/w
         rdjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TALKlaIF;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::ba as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742572064; x=1743176864; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LvHsLJh9Ue19EozP5MpThFocihOP4dkIv3j8EewJmQI=;
        b=slALd3Qs2BvXspoOmq6bvIJOPEMdQZru46rQjcHZN9HAWvyVrWMfE5IFT82ia7cVlO
         XHntwrPDLunG+qNw9BHENQSfKiEJJokeVuUT53xN1IyQOLH5WLTTbrO+kxqgtGozDb55
         d6LtP+JcWMYAap7CJ3ukbI2IPF3C7+K1ker/sX2sWITL9IWMkl1j74HU7AvjbkLn8N7z
         s6bR0VopslIVTv+xJ3xS3CPENftBLVDZQlc0I9q0H4h+ZeuXCsl5MlC65oGQTf209p+l
         nBlTzOSjV3JRS8h0vqnMoVVHnUnXPLS5PTBqzHNBcJF4HA/1FT8q+tn522KAQTRhrg2/
         ucUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742572064; x=1743176864;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LvHsLJh9Ue19EozP5MpThFocihOP4dkIv3j8EewJmQI=;
        b=cKiH+YF5fmPvxX8r8HfH0U+ZD5E5SO8Sp45xW0MUiSNoIUZWXbe4HJPtNC1TJ/9aLj
         P71PVDWcnr4U7PeAjtqAf7NkYkokwCPMy9CXlgB/FYyrawm0V+cLm5eZIQDK7NF04snp
         J9k2jjPSrEBt8JfkquIzsPut4MAvPvA4GjbtcZa/xSBAXC5cxogLopXB0GX5FxGd8pqd
         CMioBS8vuzWy1BNXgaDpTcCiLM6taXRb1T9U+gO2NVbacpUepta9NYtTdZQAIVplaLxb
         j4nMnj5FwDRd18Ase0gfBTXG+1OtQYzvAle6+XzxFtmVfUgQzFqvT6nsdZG+DWcLuPdr
         Lrzg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8r8RCwoZ15eZA+Rxk+iTS3kgq8mBZ0JIM1uvcxofdjTlR7tPCtopDFI66I0SJQIDH1qErWA==@lfdr.de
X-Gm-Message-State: AOJu0YxjG7WYjXZGYjFQeyNLsk7vMfVhJ5MICkmNIolZRoG2di5nfoB4
	y3XnkgLLnHPpsg7pjssnlmQwMpNWtTjdsmBCGksnWY6NfkB81ifO
X-Google-Smtp-Source: AGHT+IF1TfmbXr4nJFdqiLphbzOSKN4dbY4F9eivopf2NFIq01dxsaMoBvRbt/iE8T0R9H8ERS9v2Q==
X-Received: by 2002:a05:6512:3087:b0:545:ea9:1a24 with SMTP id 2adb3069b0e04-54ad647ea1fmr1424332e87.14.1742572063493;
        Fri, 21 Mar 2025 08:47:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJj9HlzoTX129W45HlejKZiEPLIXZuajQaDcLT8d2VFcQ==
Received: by 2002:a05:6512:3c6:b0:54a:c871:6d0a with SMTP id
 2adb3069b0e04-54acfc7039els16297e87.2.-pod-prod-06-eu; Fri, 21 Mar 2025
 08:47:40 -0700 (PDT)
X-Received: by 2002:a05:6512:3f1e:b0:545:109b:a9c7 with SMTP id 2adb3069b0e04-54ad64f5a24mr1578163e87.35.1742572060134;
        Fri, 21 Mar 2025 08:47:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742572060; cv=none;
        d=google.com; s=arc-20240605;
        b=eQyeIuS78AV4Z3bjCTD8Ij8sw6TdNlzSPzYqpBIY45oGowjvQCqsnpQCczVaIOIRPi
         xAWn7XCKGX+bDXee/P3zr5DG1vS0G10V7H5jnADXxHSwktsZjZ1eosSOTABSPpz3pVqW
         K0R7X9U+WIOghVE6W+GGHhpm/QwDGXywgEV3k+0xwI+T38psHAtE1w0D98eWQbGSP5bj
         ncP3iKekPxXDutt532p+0T6ixcvimNZ9cpXXIkvOmKuBkDPVAsAKS9sJw/AOBa8fB09e
         q0n+qswP4xKiuATHYlcMUwh1E42F8mF47/B+MqB9H6SxgQyjK8TZJppTCdz13WdVoQN9
         WnQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:mime-version:message-id:subject:to:from
         :dkim-signature:date;
        bh=fO+m1tDJN7wlS8HC2Z4U/2gh6MPJAhvN3NBeCSb3Nfs=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=g1E7r226eGCubPIzzefVHU8oY/a7ZBE5Y6Ps5NdvnhUQTRFTQwb13+BmDLmWAVanZ0
         NFmWii81bi0gzm/RFFYn2baJx5RRhpiBx0pQcOl+OrlNNVtpE5GhUdfInNhngSZbMJIV
         Jfkl+wTJHM2WdYk4H8RooK/B0vquYIoi1Q/HLbG8ZkiZu+GfgQzjGgXuU2NsdxbobSop
         5YtKWnnPyxLicuXjVDgphQxkEOJ2FgpmEkO5XyaduvMa5jSfkhCy7m7dfI31yI5TtyyV
         S8Nmb0TB0U791cG53E7KE/2Y/6XCivB5KtAz1A743/XuaxOd/pUwCITT5liNNVnL/17D
         LPXw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TALKlaIF;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::ba as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-186.mta0.migadu.com (out-186.mta0.migadu.com. [2001:41d0:1004:224b::ba])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54ad6473ef3si30019e87.3.2025.03.21.08.47.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Mar 2025 08:47:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::ba as permitted sender) client-ip=2001:41d0:1004:224b::ba;
Date: Fri, 21 Mar 2025 11:47:32 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: kasan-dev@googlegroups.com
Subject: KMSAN splats with struct padding
Message-ID: <5vpovh73ejzfodl2gpdx7hqr6d5tssivk3q3ibqx7do7gqwwam@pgx44qj76bzr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=TALKlaIF;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::ba as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

I've seen a couple cases of kmsan warnings due to struct padding - or in
this case, no actual padding in the top level but a lot of fun union
games - which are probably treated as padding by the compiler.

I was under the impression that compilers not initializing padding was
getting fixed - is that not the case?

If not, perhaps we could still get some help from the compiler in the
form of a type attribute?

BUG: KMSAN: uninit-value in bch2_disk_accounting_mod+0xcc0/0x1c30
 bch2_disk_accounting_mod+0xcc0/0x1c30
 __trigger_extent+0x5a5b/0x5d20
 bch2_trigger_extent+0x7f4/0xf30
 __bch2_trans_commit+0xac9/0xc2a0
 bch2_extent_update+0x450/0x9e0
 __bch2_write_index+0xf53/0x2810
 bch2_write_point_do_index_updates+0x55e/0x940
 process_scheduled_works+0x7d9/0x1580
 worker_thread+0xc17/0x1170
 kthread+0x9c6/0xc70
 ret_from_fork+0x5c/0x80
 ret_from_fork_asm+0x11/0x20

Uninit was stored to memory at:
 bch2_disk_accounting_mod+0x17ad/0x1c30
 __trigger_extent+0x5a5b/0x5d20
 bch2_trigger_extent+0x7f4/0xf30
 __bch2_trans_commit+0xac9/0xc2a0
 bch2_extent_update+0x450/0x9e0
 __bch2_write_index+0xf53/0x2810
 bch2_write_point_do_index_updates+0x55e/0x940
 process_scheduled_works+0x7d9/0x1580
 worker_thread+0xc17/0x1170
 kthread+0x9c6/0xc70
 ret_from_fork+0x5c/0x80
 ret_from_fork_asm+0x11/0x20

Local variable acc_inum_key created at:
 __trigger_extent+0x58e7/0x5d20
 bch2_trigger_extent+0x7f4/0xf30

Bytes 20-23 of 64 are uninitialized
Memory access of size 64 starts at ffff8881d998efc0

for the code:

bool insert = !(flags & BTREE_TRIGGER_overwrite);
struct disk_accounting_pos acc_inum_key = {
	.type		= BCH_DISK_ACCOUNTING_inum,
	.inum.inum	= k.k->p.inode,
};
s64 v[3] = {
	insert ? 1 : -1,
	insert ? k.k->size : -((s64) k.k->size),
	*replicas_sectors,
};
ret = bch2_disk_accounting_mod(trans, &acc_inum_key, v, ARRAY_SIZE(v), gc);
if (ret)
	return ret;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5vpovh73ejzfodl2gpdx7hqr6d5tssivk3q3ibqx7do7gqwwam%40pgx44qj76bzr.
