Return-Path: <kasan-dev+bncBCC4R3XF44KBB7FZ4DDAMGQEFPOHJ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id AAD80BA6209
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Sep 2025 19:21:02 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-3305c08d975sf3646699a91.3
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Sep 2025 10:21:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758993661; cv=pass;
        d=google.com; s=arc-20240605;
        b=LBUPrcZMff86SygblLp54xWWwQ8xvHZo2N5tjzWkdMkKm4jqvxNbsbPb+FyIUspoHF
         yOL5nv8E1/MxFXF2cvLYBKmLHxqBLgPP1/05k883Ha1wm5MxuL2vnq3zjTXrPxO6ffMY
         e+XhNiLCLcIWhH4/W2foUSCshAo+sxs9hCAAN5NzhdGJ+REhX9ZQbInOLQzGUguXPb+c
         VaWDlxVXkQHQA3qjEIrm7WAU/MaMwC4qiZVAesZL1nl2ccXi92s8HB/tCqS+YTqg/HVE
         DPYzT0/piRNk90E7/GCiOQKvew8wuOo40zfSUBpWT8VTjvtTkq3cgvm61WZzWlXIZXMP
         RSCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=byxZKA2fkZWCweY4RXoUHb0XTUc8X63Ln7/vfF+GFZM=;
        fh=F+qHyCUQ6zRBffk2zBTLA3Te4kixYqarm3pZIdoKq6M=;
        b=T5kbVIypCN1OwbieCMqP/WeNxiu9/g+PUyhO2cfSyHzS++vrNUpQmHQegMMuBBTPyB
         3ugEG7E+Q+dr9T83XV8TYwDWCv4s0BK9/28JZqlXeh9vI2mxoJS9aYNFm9nbji7UcCD5
         BAp+E8rm0C3dYHUeoWz1faNK754EouXQXWtpEKd1oAvuZ1rmqs2o9pFQ5NCokVPfHlVW
         D0MMq7Aomuy5R0HiKNpF2Zxg7fkL1DCdBAb9hAEMxVILiBodgOBeXAy7SiptIcdGXNgW
         OW7zZ6uATNC0EkSawk6/XozpdOhW/cqjMQVSY4xEZqj9GeG5M17mEUelFyIxqM12Boam
         Gt8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="WNWK/UBb";
       spf=pass (google.com: domain of sj@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758993661; x=1759598461; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=byxZKA2fkZWCweY4RXoUHb0XTUc8X63Ln7/vfF+GFZM=;
        b=iIQCVu4Mg9RKvf9U1Xx9aVxqeErsodHfBxcBbjGzHOh3CDGIDh7n0Wav1t9M8Sb1s1
         gL5DmF43qv0wfgAZ6KjbR0dU5kZ7YARz2csZg+2YiE0T2tsjp7MRLN29dJAVJk2chyFs
         EibKtZ5Fs21coNwqUpj40uxTuPShhS3BIpC8Vuh2NsbMxrtSY0e+EoFp0JMp/GzB1F0Z
         4iBkoHMMPWZ8BoLM69yhL+pamwoDyr9ryMg4C6lSZDhs53svxDQuKalnedsB6afdqWtM
         m6tvEB6vGHUBOERD2klTR5ypHmvbsXCTgpFkYuBmSsM1HY7LrsSvtVQT+in+s5hoMhpx
         FlSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758993661; x=1759598461;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=byxZKA2fkZWCweY4RXoUHb0XTUc8X63Ln7/vfF+GFZM=;
        b=CL2+yHQKls14lVuc50AjoB2ONcgOMJHXPrstpueUZuvNzcyc3afU9KbgKsV9SyS1At
         clmVlM5tz0pMjL36vgxOArV4Wm74rfl2eq36eEEDGHHVp+T4j9deXZh5G4nI4JFFlbMb
         GVBNJFfO8Ix3Xjjulv7BQcECxMhF2ZFccvUq0lX/j1rtpA/nitQSp8sodRVhWy7cyL7k
         dxEEkT3P72N1SKyDRS8WA1UAM8fQ1pcd+QMVVC5txG1N/8VlmDuoc7HIDD3OixmTLPHi
         TJX/ulB138+VEiigTzDqf9K//WFYwqqUckn1RLODUE7kZVnZ2NDqetwQljLlFBHWGTxE
         1ISg==
X-Forwarded-Encrypted: i=2; AJvYcCUJh4vFg6/Xbja0/B3MSIjQDbJoNd9DF8CQhcEPIWDrZDqWS7oQ7h3khmI/y/ELQ7Zxf8c4Hg==@lfdr.de
X-Gm-Message-State: AOJu0YxpdOhNsHbWL5+9lSBg4QpjTQMHG1MqU6OSjggZUyBXwf0AxnRs
	4vmYSYdD+XJfiDHPiOQyJM9Hwj9sauHrXcTY5Q4IZLnAiRJD0de48Zgp
X-Google-Smtp-Source: AGHT+IHaNELFfk3qBlYndUZuC+qnq6iywtqVFfluZWvsshCkjvCOBmzdHmLk2aMPvms87P3l+BDiZg==
X-Received: by 2002:a17:90b:3b8f:b0:329:7285:6941 with SMTP id 98e67ed59e1d1-3342a2bf43dmr13982465a91.19.1758993660637;
        Sat, 27 Sep 2025 10:21:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7/O6XlihMv0vMGfTOHCzbb46d3qEL5M2oYTg8+gxIZow=="
Received: by 2002:a17:90b:28c3:b0:336:c0f7:fba4 with SMTP id
 98e67ed59e1d1-336c0f814f1ls239822a91.1.-pod-prod-04-us; Sat, 27 Sep 2025
 10:20:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/G+6mAjRwr8ywQgiR8YPUBR+R8gu10Vao/VhRMMU8UZqhnGE3KY1StN8ZN3AQVZkZSSnZ7iDvJ84=@googlegroups.com
X-Received: by 2002:a17:90b:5109:b0:330:9fe7:b014 with SMTP id 98e67ed59e1d1-3342a2ebce9mr9980651a91.31.1758993659026;
        Sat, 27 Sep 2025 10:20:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758993659; cv=none;
        d=google.com; s=arc-20240605;
        b=Q0ZQs2+oc2rfFuKfHYln2SasLv0g6ZiWhwvQMjdnYmLRXvClVK5+G+ggeOt9Wq1qRl
         cK3O5DlYtGnlEQ93fIlZsM1eGbxJ0H9JBsey/+LyeFTVKiPfPEx/fAxMtXjXhqOYUXmh
         HPKKBM8PvV0kcBQL2UiKqB9Mu2TCgFzDim2LtdIo+5vc5xIJ9diW6WCCQrumlq9HVnyc
         1/aKbx11O5mp7tOAMUJldSGxZzoH7ffxwsKKXx+EIAfvxT5scqaHgd4g00sqHE96DLj6
         mC6AWQOLWuF6wmCuGyOE0VW+k6eMJOO6AQa3PQaD1HgKdp1UcJFDI9V+XXdQdmCklWi6
         gptA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QPFvFZpqjscR7nfqaX6NJJDHRV9COk9d8n8OMCkc0sk=;
        fh=gsiXB1Iq+hulXf5Tr2I4HuoEe8f8vxMKvoXtlAywlaY=;
        b=Fhgxg1nWSPvhNgF6cvtecq7oo6l5sazBHja6JlkVBE19QOIhX2DMiknqBjgj7snzO4
         tjq5W94vqFGRSCZnyLYOzT895n9hOVNGzVi6k5YoHhbsz9uzpcHjRdsIzGuM71mzLJd5
         kKGNTOqMvBqMxkZsngvdNuc9YBC6UZ0FKbKSzi3d2O7N5k7XRWPGYm3yLDEyQSCbxhwr
         hS0EQgDmyc/x+OYgUWetFpD9wbq5Gq9VTAdVoaXxTSyk+e54K2CWr/amugvVemnR9EuH
         4xSeGKrS2l+uCd6DG/dux32P3SdWIFtGq96PSAyBcs09C/2eD9CPVZRDtHCkxiOuuu+5
         Hvqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="WNWK/UBb";
       spf=pass (google.com: domain of sj@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-334315e6be8si273819a91.1.2025.09.27.10.20.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 27 Sep 2025 10:20:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id D8BF0620A7;
	Sat, 27 Sep 2025 17:20:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 59D47C4CEE7;
	Sat, 27 Sep 2025 17:20:57 +0000 (UTC)
From: "'SeongJae Park' via kasan-dev" <kasan-dev@googlegroups.com>
To: "jianyun.gao" <jianyungao89@gmail.com>
Cc: SeongJae Park <sj@kernel.org>,
	linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	John Hubbard <jhubbard@nvidia.com>,
	Peter Xu <peterx@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Xu Xin <xu.xin16@zte.com.cn>,
	Chengming Zhou <chengming.zhou@linux.dev>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Christoph Lameter <cl@gentwo.org>,
	David Rientjes <rientjes@google.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Harry Yoo <harry.yoo@oracle.com>,
	Kemeng Shi <shikemeng@huaweicloud.com>,
	Kairui Song <kasong@tencent.com>,
	Nhat Pham <nphamcs@gmail.com>,
	Baoquan He <bhe@redhat.com>,
	Barry Song <baohua@kernel.org>,
	Chris Li <chrisl@kernel.org>,
	Jann Horn <jannh@google.com>,
	Pedro Falcato <pfalcato@suse.de>,
	damon@lists.linux.dev (open list:DATA ACCESS MONITOR),
	linux-kernel@vger.kernel.org (open list),
	kasan-dev@googlegroups.com (open list:KMSAN)
Subject: Re: [PATCH] mm: Fix some typos in mm module
Date: Sat, 27 Sep 2025 10:20:55 -0700
Message-Id: <20250927172055.54527-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250927080635.1502997-1-jianyungao89@gmail.com>
References: 
MIME-Version: 1.0
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="WNWK/UBb";       spf=pass
 (google.com: domain of sj@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=sj@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: SeongJae Park <sj@kernel.org>
Reply-To: SeongJae Park <sj@kernel.org>
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

On Sat, 27 Sep 2025 16:06:34 +0800 "jianyun.gao" <jianyungao89@gmail.com> wrote:

> Below are some typos in the code comments:
> 
>   intevals ==> intervals
>   addesses ==> addresses
>   unavaliable ==> unavailable
>   facor ==> factor
>   droping ==> dropping
>   exlusive ==> exclusive
>   decription ==> description
>   confict ==> conflict
>   desriptions ==> descriptions
>   otherwize ==> otherwise
>   vlaue ==> value
>   cheching ==> checking
>   exisitng ==> existing
>   modifed ==> modified
> 
> Just fix it.

Thank you for fixing those!

> 
> Signed-off-by: jianyun.gao <jianyungao89@gmail.com>

Reviewed-by: SeongJae Park <sj@kernel.org>


Thanks,
SJ

[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250927172055.54527-1-sj%40kernel.org.
