Return-Path: <kasan-dev+bncBAABBCE26HFQMGQE2RP3UMY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id m04CMgpNfGlwLwIAu9opvQ
	(envelope-from <kasan-dev+bncBAABBCE26HFQMGQE2RP3UMY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 07:17:46 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 55EB0B7965
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 07:17:46 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-658102e94c6sf2024115a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 22:17:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769753865; cv=pass;
        d=google.com; s=arc-20240605;
        b=VEvh3fro4n99oXxwBOC9aE2nBxzVanCePsZspetDsOZW9jN88cU4CEKrk+bkKOIkGK
         Jd870VAfmfCr+MwPWX9cTzf17uWQ08vLsV2zMHghJOX4mdv8ZTiCH33YmK7AgnzBAwSB
         +uG/4Hq6nB9NWXmYxgIe3KLGoi120xHvoEd8XAKkfdWf86M+xo4YABKN+iaDTkBOtn0U
         upL41fcbRefR+eyVJFWyoKV0V9aVn3j5ufyuxnx+AczFJPoYVyHtB6PX/rxFGTOHg3ec
         KYlvCaaLCRQikN9qDtLWXGDkZWA9cgTGqDPKFDbaLXPGaqt1bmeclKemVeoADMZy1hli
         GAcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/f+opjOae6Eb0c91bH9tvLYi2LtjixBPIaPAcQVPfOo=;
        fh=hwm6S6PwNKdjnlQC5hqMEVd/4RwP4XGE6AaiqxQLa+w=;
        b=T4LARd109n8LFdUnWnICQcK2YbEJDYlaFwDassgdGWTYxVBTNYhBYrYJwxkTLCAIvF
         SwdC7kd3wvGisFrSqY28cNEEbF0LhSb5f5+HZUn9oPPQQevIRQhD/oypxVQffROufTZI
         yK2Ij7WbURMRHoOwZv0XEiF8LARpB3nbLrdnlWl9Ug5Q7XOLKL6DYvUzegGhS6LHStuw
         Q1OzjrZO1k786XUgBrgKOWuxOdNk3P/mrpmnZvbID5LHe95mn7ln/qWg9Sn82WbuC8GF
         7tpBdDfIetEp29Ls2B9lqCSYKIDcBnQxYNlFSvWlI9FSU5pkVrPQtdJtdFKiMaRQTudf
         5SZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="uh/m2RGZ";
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::bc as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769753865; x=1770358665; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/f+opjOae6Eb0c91bH9tvLYi2LtjixBPIaPAcQVPfOo=;
        b=QOhefh0pa+JJYIuOp1JBnzlGcez3ZcY5ll3WS5xuU6GN256+xDHj6XW7RS6btXCIX0
         kckT1Y7vAIngzP2ppVKHMnRn3L4RTMY3uVbJl/ZNF/Z5nRcVuyfrdYFKh8qTnyYl93sU
         034gCRaWzXLmM/tEzgcMX2FIImkPDiu63hUTwhHHX5G2KtpT9TaSum2LrsC+Cp9eMXBE
         2Gd9y1RFRoLOMSqxwyshTtqdf9A9UcDRIIFuVA5iL1I4W7MLRSJMQytJ4g+k4PSQT6ZC
         jgnW3fkxM1S2ncKw7KXZn37NDcHcp7yyDECwzBfL3KSE9Mod+xT/ov0wT+ffkLiiCdyp
         IyMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769753865; x=1770358665;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/f+opjOae6Eb0c91bH9tvLYi2LtjixBPIaPAcQVPfOo=;
        b=o+M6C47t8uhPpkDmLlqW0XOJa2QSLiQbpDfvv7OwytOwxNFRWVRsNwVZ2mSc4dfOf/
         QAkku0dMBZlnmOoPs6Z/NUq6mgQOVFqv0t3GiPYv2YlKhtz3WuMN4SvbIuj0KAji9ugB
         JUQjqm1Y1tEiQZH391QCgBU3X3PodlT9QMnw7l8DiICIBYO3KShWIfxrs/x4OKg4JF1q
         OODYyLkcIdp3gODeMrXcE3VA/vRYe6ewN5v1auwJ9Z+GpVuga/eBSPwGwlLT4fNUeUdc
         zJE9wgJZKneD8kOMZ81vpreGRMeyyE1yIZVG6SGy/HENB7H9XlsW28DMztAY2j4U4wTU
         Qc7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXEMZYDMODh1DlTY2AIxG0pWpp64fVAZY7V6W3/xUcvv6eK/xAuF9Bej00Ljn/32OFJJb7W9w==@lfdr.de
X-Gm-Message-State: AOJu0YwTnWBcH0yvHsbyNDL0p56mOKcIypG1TwbWuK3YlPhoq3LEOjj6
	3BJkYyhQr9JphEV+LtDDfs4Tsg6H925BuGeKNVXMTjYAzLI+kazcyLmp
X-Received: by 2002:a05:6402:144a:b0:64f:d03a:9af4 with SMTP id 4fb4d7f45d1cf-658de5437e4mr1254037a12.3.1769753865407;
        Thu, 29 Jan 2026 22:17:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GSTazO60nZs6rrqau1MHzsvn6iFTmx5sQn9q2Lh2kWHA=="
Received: by 2002:aa7:d482:0:b0:658:bdf4:dbb6 with SMTP id 4fb4d7f45d1cf-658ccb4f71als1193827a12.0.-pod-prod-06-eu;
 Thu, 29 Jan 2026 22:17:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXuDSUMz05CvOtwa7KbvV7HaMqTxwysJBxcrL38dU5igralS3ltRYmBiTdLi+cnQHlPOXE+DaSk/QU=@googlegroups.com
X-Received: by 2002:a05:6402:4416:b0:658:3652:a0be with SMTP id 4fb4d7f45d1cf-658de5acd67mr979416a12.31.1769753863624;
        Thu, 29 Jan 2026 22:17:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769753863; cv=none;
        d=google.com; s=arc-20240605;
        b=Qqztem7dZphcc6erNvAT6CIfPqxxY7FjLbVfUNbyPMn4VQ7S+hsEqncu4giqEari90
         79Msh/G5L4X2Xlc6xmupRFKE6IOyft/Ov1btvLRt+dqMrfP2PYyRxlIALVehoieLoDgB
         e51vNTGPzRr2yKzucmZVePNmc2bWt/lCsyId1SZvmwpNc3701DhR7qNoN+kS0qBzKozn
         yVcceeupR3Ys+SXAqHJwJkYz/UXWktvEyWkr8ifFpLy2n1eBQ3KCNNXCg5NK6CP82Tzh
         GbEPL9PNLDoSOeDYADqNFK0a15cLyZQ9HJY4ljL0KJN7E1TXsMWDVwcOTdrbEH64swG9
         PEKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=Oc43I2XjtgSCW/lhB/Z+tW4u7IMzTAGJYJqdI4VSEG8=;
        fh=IJc/xULCf01o48qWj7VfHKXKmbbWC8yCQEzHfREZ7bs=;
        b=FxJsAyumbViGDScjOamAarve3tIhtgLaRbKhULem7g8aPhdTrWo1N8MPFacOiv3FDr
         phzCjHxsD9/v3u38x0S/oUJZjqRVf4dXEydKbnJMqSCIY5AMQyCaTJVAzGVCEpG2OQHk
         D6yTaR2Z9FZHFSuU+DrhePXniL7q+JpVmeJ5NSPur8qlUFhUWEadXDyjPRfquJrri0Fj
         TPE0KBxggBI9dNHzloCwC0kL5qWEP4S3pTZQ6aDLLTCYyKphRAahXji8EW8PW0bRjiAN
         Gw8SW4DGm3s2NgpLjNk2ufO8+Q75oDd/KT3U235tfAiXYDxxr5SCCDPkPjJmNNA1Js3x
         +E0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="uh/m2RGZ";
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::bc as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-188.mta0.migadu.com (out-188.mta0.migadu.com. [2001:41d0:1004:224b::bc])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-658b47d1c37si163088a12.5.2026.01.29.22.17.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jan 2026 22:17:43 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::bc as permitted sender) client-ip=2001:41d0:1004:224b::bc;
Date: Fri, 30 Jan 2026 14:17:32 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
	kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org, "Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH v4 00/22] slab: replace cpu (partial) slabs with sheaves
Message-ID: <oj5ossmsvybogs5fr2fjdmms66usoh7pdpkuxwlkagxniscrrb@vghtzkxauvix>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <imzzlzuzjmlkhxc7hszxh5ba7jksvqcieg5rzyryijkkdhai5q@l2t4ye5quozb>
 <390d6318-08f3-403b-bf96-4675a0d1fe98@suse.cz>
 <pdmjsvpkl5nsntiwfwguplajq27ak3xpboq3ab77zrbu763pq7@la3hyiqigpir>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <pdmjsvpkl5nsntiwfwguplajq27ak3xpboq3ab77zrbu763pq7@la3hyiqigpir>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="uh/m2RGZ";       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::bc as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.11 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBAABBCE26HFQMGQE2RP3UMY];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 55EB0B7965
X-Rspamd-Action: no action

On Fri, Jan 30, 2026 at 12:50:25PM +0800, Hao Li wrote:
> On Thu, Jan 29, 2026 at 04:28:01PM +0100, Vlastimil Babka wrote:
> > 
> > So previously those would become kind of double
> > cached by both sheaves and cpu (partial) slabs (and thus hopefully benefited
> > more than they should) since sheaves introduction in 6.18, and now they are
> > not double cached anymore?
> > 
> 
> I've conducted new tests, and here are the details of three scenarios:
> 
>   1. Checked out commit 9d4e6ab865c4, which represents the state before the
>      introduction of the sheaves mechanism.
>   2. Tested with 6.19-rc5, which includes sheaves but does not yet apply the
>      "sheaves for all" patchset.
>   3. Applied the "sheaves for all" patchset and also included the "avoid
>      list_lock contention" patch.

Here is my testing environment information and the raw test data.

Command:

cd will-it-scale/
python3 ./runtest.py mmap2 25 process 0 0 64 128 192

Env:

CPU(s):                                  192
Thread(s) per core:                      1
Core(s) per socket:                      96
Socket(s):                               2
NUMA node(s):                            4
NUMA node0 CPU(s):                       0-47
NUMA node1 CPU(s):                       48-95
NUMA node2 CPU(s):                       96-143
NUMA node3 CPU(s):                       144-191
Memory:                                  1.5T

Raw data:

1. Checked out commit 9d4e6ab865c4, which represents the state before the
   introduction of the sheaves mechanism.

{
  "time.elapsed_time": 93.88,
  "time.elapsed_time.max": 93.88,
  "time.file_system_inputs": 2640,
  "time.file_system_outputs": 128,
  "time.involuntary_context_switches": 417738,
  "time.major_page_faults": 54,
  "time.maximum_resident_set_size": 90012,
  "time.minor_page_faults": 80569,
  "time.page_size": 4096,
  "time.percent_of_cpu_this_job_got": 5707,
  "time.system_time": 5272.97,
  "time.user_time": 85.59,
  "time.voluntary_context_switches": 2436,
  "will-it-scale.128.processes": 28445014,
  "will-it-scale.128.processes_idle": 33.89,
  "will-it-scale.192.processes": 39899678,
  "will-it-scale.192.processes_idle": 1.29,
  "will-it-scale.64.processes": 15645502,
  "will-it-scale.64.processes_idle": 66.75,
  "will-it-scale.per_process_ops": 224832,
  "will-it-scale.time.elapsed_time": 93.88,
  "will-it-scale.time.elapsed_time.max": 93.88,
  "will-it-scale.time.file_system_inputs": 2640,
  "will-it-scale.time.file_system_outputs": 128,
  "will-it-scale.time.involuntary_context_switches": 417738,
  "will-it-scale.time.major_page_faults": 54,
  "will-it-scale.time.maximum_resident_set_size": 90012,
  "will-it-scale.time.minor_page_faults": 80569,
  "will-it-scale.time.page_size": 4096,
  "will-it-scale.time.percent_of_cpu_this_job_got": 5707,
  "will-it-scale.time.system_time": 5272.97,
  "will-it-scale.time.user_time": 85.59,
  "will-it-scale.time.voluntary_context_switches": 2436,
  "will-it-scale.workload": 83990194
}

2. Tested with 6.19-rc5, which includes sheaves but does not yet apply the
   "sheaves for all" patchset.

{
  "time.elapsed_time": 93.86000000000001,
  "time.elapsed_time.max": 93.86000000000001,
  "time.file_system_inputs": 1952,
  "time.file_system_outputs": 160,
  "time.involuntary_context_switches": 766225,
  "time.major_page_faults": 50.666666666666664,
  "time.maximum_resident_set_size": 90012,
  "time.minor_page_faults": 80635,
  "time.page_size": 4096,
  "time.percent_of_cpu_this_job_got": 5738,
  "time.system_time": 5251.88,
  "time.user_time": 134.57666666666665,
  "time.voluntary_context_switches": 2539,
  "will-it-scale.128.processes": 38223543.333333336,
  "will-it-scale.128.processes_idle": 33.833333333333336,
  "will-it-scale.192.processes": 54039039,
  "will-it-scale.192.processes_idle": 1.26,
  "will-it-scale.64.processes": 20579207.666666668,
  "will-it-scale.64.processes_idle": 66.74333333333334,
  "will-it-scale.per_process_ops": 300541,
  "will-it-scale.time.elapsed_time": 93.86000000000001,
  "will-it-scale.time.elapsed_time.max": 93.86000000000001,
  "will-it-scale.time.file_system_inputs": 1952,
  "will-it-scale.time.file_system_outputs": 160,
  "will-it-scale.time.involuntary_context_switches": 766225,
  "will-it-scale.time.major_page_faults": 50.666666666666664,
  "will-it-scale.time.maximum_resident_set_size": 90012,
  "will-it-scale.time.minor_page_faults": 80635,
  "will-it-scale.time.page_size": 4096,
  "will-it-scale.time.percent_of_cpu_this_job_got": 5738,
  "will-it-scale.time.system_time": 5251.88,
  "will-it-scale.time.user_time": 134.57666666666665,
  "will-it-scale.time.voluntary_context_switches": 2539,
  "will-it-scale.workload": 112841790
}

3. Applied the "sheaves for all" patchset and also included the "avoid
   list_lock contention" patch.

{
  "time.elapsed_time": 93.86666666666667,
  "time.elapsed_time.max": 93.86666666666667,
  "time.file_system_inputs": 1800,
  "time.file_system_outputs": 149.33333333333334,
  "time.involuntary_context_switches": 421120,
  "time.major_page_faults": 37,
  "time.maximum_resident_set_size": 90016,
  "time.minor_page_faults": 80645,
  "time.page_size": 4096,
  "time.percent_of_cpu_this_job_got": 5714.666666666667,
  "time.system_time": 5256.176666666667,
  "time.user_time": 108.88333333333333,
  "time.voluntary_context_switches": 2513,
  "will-it-scale.128.processes": 28067051.333333332,
  "will-it-scale.128.processes_idle": 33.82,
  "will-it-scale.192.processes": 38232965.666666664,
  "will-it-scale.192.processes_idle": 1.2733333333333334,
  "will-it-scale.64.processes": 15464041.333333334,
  "will-it-scale.64.processes_idle": 66.76333333333334,
  "will-it-scale.per_process_ops": 220009.33333333334,
  "will-it-scale.time.elapsed_time": 93.86666666666667,
  "will-it-scale.time.elapsed_time.max": 93.86666666666667,
  "will-it-scale.time.file_system_inputs": 1800,
  "will-it-scale.time.file_system_outputs": 149.33333333333334,
  "will-it-scale.time.involuntary_context_switches": 421120,
  "will-it-scale.time.major_page_faults": 37,
  "will-it-scale.time.maximum_resident_set_size": 90016,
  "will-it-scale.time.minor_page_faults": 80645,
  "will-it-scale.time.page_size": 4096,
  "will-it-scale.time.percent_of_cpu_this_job_got": 5714.666666666667,
  "will-it-scale.time.system_time": 5256.176666666667,
  "will-it-scale.time.user_time": 108.88333333333333,
  "will-it-scale.time.voluntary_context_switches": 2513,
  "will-it-scale.workload": 81764058.33333333
}

> 
> 
> Results:
> 
> For scenario 2 (with sheaves but without "sheaves for all"), there is a
> noticeable performance improvement compared to scenario 1:
> 
> will-it-scale.128.processes +34.3%
> will-it-scale.192.processes +35.4%
> will-it-scale.64.processes +31.5%
> will-it-scale.per_process_ops +33.7%
> 
> For scenario 3 (after applying "sheaves for all"), performance slightly
> regressed compared to scenario 1:
> 
> will-it-scale.128.processes -1.3%
> will-it-scale.192.processes -4.2%
> will-it-scale.64.processes -1.2%
> will-it-scale.per_process_ops -2.1%
> 
> Analysis:
> 
> So when the sheaf size for maple nodes is set to 32 by default, the performance
> of fully adopting the sheaves mechanism roughly matches the performance of the
> previous approach that relied solely on the percpu slab partial list.
> 
> The performance regression observed with the "sheaves for all" patchset can
> actually be explained as follows: moving from scenario 1 to scenario 2
> introduces an additional cache layer, which boosts performance temporarily.
> When moving from scenario 2 to scenario 3, this additional cache layer is
> removed, then performance reverted to its original level.
> 
> So I think the performance of the percpu partial list and the sheaves mechanism
> is roughly the same, which is consistent with our expectations.
> 
> -- 
> Thanks,
> Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/oj5ossmsvybogs5fr2fjdmms66usoh7pdpkuxwlkagxniscrrb%40vghtzkxauvix.
